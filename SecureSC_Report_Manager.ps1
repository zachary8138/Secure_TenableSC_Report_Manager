<#
Tenable.sc reporting helper

What this script does
- Optionally creates/updates `config.json` containing one or more Tenable.sc "Security Center" entries:
  - `url`: base URL for the Tenable.sc instance
  - `encrypted_key`: encrypted `accessKey;secretKey` bundle
- Queries reports within a time window and downloads matching PDF/CSV reports to a timestamped output folder.

Security notes (important)
- This script encrypts API keys for storage at rest, but the keys are still decrypted in-memory during execution.
- The encryption key is supplied via the `FERNET` environment variable (base64-encoded 32 bytes).
- Prefer running with least-privilege API keys (read-only/report download scope only).
- Keep `config.json` and output logs in protected locations; logs intentionally avoid printing secrets.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsWindowsOS = $null
try { $script:IsWindowsOS = (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue).Value } catch { }
if ($null -eq $script:IsWindowsOS) { $script:IsWindowsOS = ($env:OS -eq 'Windows_NT') }

Function ConvertFrom-SecureStringPlainText {
    param([Parameter(Mandatory)] [securestring] $SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

Function Test-FixedTimeEquals {
    param(
        [Parameter(Mandatory)] [byte[]] $A,
        [Parameter(Mandatory)] [byte[]] $B
    )
    if ($A.Length -ne $B.Length) { return $false }

    $cryptoOpsType = [type]::GetType('System.Security.Cryptography.CryptographicOperations')
    if ($null -ne $cryptoOpsType) {
        $m = $cryptoOpsType.GetMethod('FixedTimeEquals', [type[]]@([byte[]],[byte[]]))
        if ($null -ne $m) {
            return $m.Invoke($null, @($A, $B))
        }
    }

    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
        $diff = $diff -bor ($A[$i] -bxor $B[$i])
    }
    return ($diff -eq 0)
}

Function Load-FernetKey {
    if ([string]::IsNullOrWhiteSpace($Env:FERNET)) {
        throw "FERNET environment variable is not set."
    }
    try {
        $key = [Convert]::FromBase64String($Env:FERNET)
    } catch {
        throw "FERNET environment variable is not valid base64."
    }
    if ($key.Length -ne 32) {
        throw "FERNET key must decode to exactly 32 bytes (256 bits)."
    }
    return $key
}

# Encrypt `accessKey;secretKey` using AES-CBC with random IV, plus HMAC-SHA256 for integrity (encrypt-then-MAC).
# Stored format (base64): HMAC(32 bytes) || IV(16 bytes) || CIPHERTEXT(n bytes)
Function Encrypt-ApiKeys {
    param (
        [Parameter(Mandatory)] [string]$AccessKey,
        [Parameter(Mandatory)] [string]$SecretKey
    )

    $fernetKey = Load-FernetKey

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $fernetKey
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor()
    $combinedKey = "${AccessKey};${SecretKey}"
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($combinedKey)
    $ciphertext = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)

    $dataToMac = $iv + $ciphertext
    $hmac = New-Object System.Security.Cryptography.HMACSHA256($fernetKey)
    $tag = $hmac.ComputeHash($dataToMac)

    return [Convert]::ToBase64String($tag + $dataToMac)
}
 
# Function to create or update the JSON configuration file
Function Create-ConfigFile {
    param (
        [string]$FileName = "config.json",
        [hashtable]$ConfigData
    )
 
    if (Test-Path $FileName) {
        Write-Output "$FileName already exists. Merging new entries with the existing configuration."
        $existingData = Get-Content $FileName | ConvertFrom-Json
        $existingHashtable = @{}
        foreach ($property in $existingData.PSObject.Properties) {
            $existingHashtable[$property.Name] = $property.Value
        }
        foreach ($key in $ConfigData.Keys) {
            $existingHashtable[$key] = $ConfigData[$key]
        }
        $existingHashtable | ConvertTo-Json -Depth 10 | Set-Content -Path $FileName -Force
    } else {
        $ConfigData | ConvertTo-Json -Depth 10 | Set-Content -Path $FileName -Force
    }
    Write-Output "Configuration saved to $FileName"

    # Best-effort: restrict permissions (Windows ACL / Linux chmod). Ignore failures.
    try {
        if ($script:IsWindowsOS) {
            # Keep simple: remove inherited permissions and grant current user full control.
            $acl = Get-Acl -Path $FileName
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl -Path $FileName -AclObject $acl
        } else {
            & chmod 600 -- $FileName 2>$null
        }
    } catch { }
}

Function Test-UrlIsHttps {
    param([Parameter(Mandatory)][string]$Url)
    try {
        $uri = [System.Uri]$Url
        return $uri.Scheme -eq 'https'
    } catch {
        return $false
    }
}

Function Invoke-ConfigSetup {
    $configFile = "config.json"

    # Fail fast if no encryption key; don't prompt for secrets without a key.
    try { $null = Load-FernetKey }
    catch {
        Write-Output "FERNET key not available. Generate/set the key before continuing."
        Write-Output "Hint: run your key generation script and set `FERNET` (base64-encoded 32 bytes)."
        return
    }

    if (Test-Path $configFile) {
        Write-Output "Choose an option:"
        Write-Output "1. Add/Update Security Centers in the existing configuration."
        Write-Output "2. Wipe the existing configuration file (does not unset FERNET on non-Windows shells)."

        $option = Read-Host "Enter 1 or 2"
        switch ($option) {
            "1" { }
            "2" {
                $confirm = Read-Host "Type YES to confirm wiping $configFile"
                if ($confirm -ne "YES") {
                    Write-Output "Operation canceled."
                    return
                }
                Remove-Item -Path $configFile -ErrorAction SilentlyContinue
                Write-Output "Existing config file deleted. Starting fresh."
            }
            default {
                Write-Output "Invalid choice. Exiting."
                return
            }
        }
    }

    $securityCenters = @{}

    while ($true) {
        $centerName = Read-Host "Enter a name for the Security Center (e.g., acas1)"
        if ([string]::IsNullOrWhiteSpace($centerName)) {
            Write-Output "Security Center name cannot be empty."
            continue
        }

        $url = Read-Host "Enter the HTTPS URL for $centerName (e.g., https://tenable.example)"
        if (-not (Test-UrlIsHttps -Url $url)) {
            Write-Output "URL must be a valid HTTPS URL."
            continue
        }

        $accessKey = Read-Host "Enter the Access Key for $centerName"
        $secretKeySecure = Read-Host "Enter the Secret Key for $centerName" -AsSecureString
        $secretKey = ConvertFrom-SecureStringPlainText -SecureString $secretKeySecure

        try {
            $encryptedKey = Encrypt-ApiKeys -AccessKey $accessKey -SecretKey $secretKey
        } finally {
            # Best-effort: drop plaintext copy ASAP
            $secretKey = $null
        }

        $securityCenters[$centerName] = @{
            url = $url
            encrypted_key = $encryptedKey
        }

        $more = Read-Host "Add another Security Center? (yes/no)"
        if ($more -ne "yes") { break }
    }

    Create-ConfigFile -ConfigData $securityCenters
}
 
# Configuration
$Config = @{
    MaxRetries = 3
    RetryDelay = 5
    TimeoutSeconds = 30
    LogLevel = "INFO"  # DEBUG, INFO, WARNING, ERROR
}

# Logging function
Function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "DEBUG" { if ($Config.LogLevel -in @("DEBUG")) { Write-Host $logMessage -ForegroundColor Gray } }
        "INFO" { if ($Config.LogLevel -in @("DEBUG", "INFO")) { Write-Host $logMessage -ForegroundColor White } }
        "WARNING" { if ($Config.LogLevel -in @("DEBUG", "INFO", "WARNING")) { Write-Host $logMessage -ForegroundColor Yellow } }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    Add-Content -Path $script:LogFile -Value $logMessage
}

# Function to validate and sanitize input
Function Test-Input {
    param(
        [string]$Input,
        [string]$Type
    )
    switch ($Type) {
        "Date" {
            try {
                $date = [DateTime]::ParseExact($Input, "yyyy-MM-dd HH:mm", $null)
                return $true
            } catch {
                Write-Log "Invalid date format. Expected: YYYY-MM-DD HH:MM" -Level "ERROR"
                return $false
            }
        }
        "Url" {
            try {
                $uri = [System.Uri]$Input
                return $uri.Scheme -eq "https"
            } catch {
                Write-Log "Invalid URL format" -Level "ERROR"
                return $false
            }
        }
        "FileName" {
            return $Input -match '^[^<>:"/\\|?*]+$'
        }
    }
}

# Function to decrypt the encrypted access and secret keys
Function Decrypt-ApiKeys {
    param (
        [string]$EncryptedKey
    )
    try {
        $fernetKey = Load-FernetKey
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $fernetKey
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $encryptedData = [Convert]::FromBase64String($EncryptedKey)
        if ($encryptedData.Length -lt (32 + 16 + 1)) {
            throw "Encrypted key payload too short."
        }

        $tag = $encryptedData[0..31]
        $data = $encryptedData[32..($encryptedData.Length - 1)]

        $hmac = New-Object System.Security.Cryptography.HMACSHA256($fernetKey)
        $expectedTag = $hmac.ComputeHash($data)
        if (-not (Test-FixedTimeEquals -A $tag -B $expectedTag)) {
            throw "Encrypted key integrity check failed (HMAC mismatch)."
        }

        $iv = $data[0..15]
        $ciphertext = $data[16..($data.Length - 1)]
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plaintextBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        return [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
    } catch {
        Write-Log "Failed to decrypt key: $_" -Level "ERROR"
        throw
    }
}

# Function to load the configuration file
Function Load-ConfigFile {
    param (
        [string]$ConfigPath = "config.json"
    )
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found: $ConfigPath" -Level "ERROR"
        throw "Configuration file not found: $ConfigPath"
    }
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        foreach ($center in $config.PSObject.Properties) {
            if (-not (Test-Input -Input $center.Value.url -Type "Url")) {
                throw "Invalid URL in configuration for $($center.Name)"
            }
        }
        return $config
    } catch {
        Write-Log "Failed to load configuration: $_" -Level "ERROR"
        throw
    }
}

# Function to query Tenable using Invoke-RestMethod
Function Query-Tenable {
    param (
        [string]$TenableUrl,
        [string]$ApiKey,
        [int]$StartEpoch,
        [int]$EndEpoch
    )
    $retryCount = 0
    while ($retryCount -lt $Config.MaxRetries) {
        try {
            $headers = @{
                "x-apikey" = $ApiKey
                "Content-Type" = "application/json"
            }
            
            $response = Invoke-RestMethod -Uri "$TenableUrl/rest/report?fields=id,name,type,finishTime" `
                                        -Headers $headers `
                                        -Method Get `
                                        -TimeoutSec $Config.TimeoutSeconds `
                                        -ErrorAction Stop

            $reports = $response.response.usable
            $filteredReports = $reports | Where-Object {
                $_.type -in @("pdf", "csv") -and 
                $_.finishTime -and 
                ($_.finishTime -as [int]) -ge $StartEpoch -and 
                ($_.finishTime -as [int]) -le $EndEpoch
            }
            return $filteredReports
        } catch {
            $retryCount++
            if ($retryCount -eq $Config.MaxRetries) {
                Write-Log "Failed to query Tenable after $($Config.MaxRetries) attempts: $_" -Level "ERROR"
                throw
            }
            Write-Log "Query attempt $retryCount failed. Retrying in $($Config.RetryDelay) seconds..." -Level "WARNING"
            Start-Sleep -Seconds $Config.RetryDelay
        }
    }
}

# Function to sanitize file names
Function Sanitize-FileName {
    param ([string]$FileName)
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $sanitized = $FileName
    foreach ($char in $invalidChars) {
        $sanitized = $sanitized.Replace($char, '_')
    }
    return $sanitized
}

# Function to download a report using Invoke-RestMethod
Function Download-Report {
    param (
        [Object]$Report,
        [string]$TenableUrl,
        [string]$ApiKey,
        [string]$ReportsFolder
    )
    $reportId = $Report.id
    $reportName = Sanitize-FileName -FileName $Report.name
    $fileType = $Report.type.ToLower()
    $reportPath = Join-Path $ReportsFolder "$reportName.$fileType"
    
    $retryCount = 0
    while ($retryCount -lt $Config.MaxRetries) {
        try {
            $headers = @{
                "x-apikey" = $ApiKey
                "Content-Type" = "application/json"
            }
            
            $null = Invoke-RestMethod -Uri "$TenableUrl/rest/report/$reportId/download" `
                                        -Headers $headers `
                                        -Method Post `
                                        -TimeoutSec $Config.TimeoutSeconds `
                                        -OutFile $reportPath `
                                        -ErrorAction Stop

            # Verify file was downloaded
            if (Test-Path $reportPath) {
                $fileInfo = Get-Item $reportPath
                if ($fileInfo.Length -gt 0) {
                    Write-Log "Successfully downloaded report: $reportName.$fileType" -Level "INFO"
                    return $true
                }
            }
            throw "File download verification failed"
        } catch {
            $retryCount++
            if ($retryCount -eq $Config.MaxRetries) {
                Write-Log "Failed to download report after $($Config.MaxRetries) attempts: $_" -Level "ERROR"
                return $false
            }
            Write-Log "Download attempt $retryCount failed. Retrying in $($Config.RetryDelay) seconds..." -Level "WARNING"
            Start-Sleep -Seconds $Config.RetryDelay
        }
    }
    return $false
}

Function Invoke-ReportDownload {
    $outputFolderName = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_Tenable-Reports"
    $outputFolder = Join-Path (Get-Location) $outputFolderName
    $reportsFolder = Join-Path $outputFolder "reports"
    $script:LogFile = Join-Path $outputFolder "$outputFolderName.log"

    try {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null

        Write-Log "Starting Tenable Reports download process" -Level "INFO"
        
        $fernetKey = Load-FernetKey
        $config = Load-ConfigFile

        do {
            $startDate = Read-Host "Enter the start date (YYYY-MM-DD HH:MM)"
        } while (-not (Test-Input -Input $startDate -Type "Date"))

        do {
            $endDate = Read-Host "Enter the end date (YYYY-MM-DD HH:MM)"
        } while (-not (Test-Input -Input $endDate -Type "Date"))

        $startEpoch = [DateTimeOffset]::ParseExact($startDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()
        $endEpoch = [DateTimeOffset]::ParseExact($endDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()

        foreach ($centerName in $config.PSObject.Properties.Name) {
            Write-Log "Processing Security Center: $centerName" -Level "INFO"
            
            $centerInfo = $config.$centerName
            $tenableUrl = $centerInfo.url
            $encryptedKey = $centerInfo.encrypted_key
            
            try {
                $decryptedKey = Decrypt-ApiKeys -EncryptedKey $encryptedKey
                $keys = $decryptedKey -split ";"
                if ($keys.Count -lt 2) {
                    throw "Decrypted key material was not in expected format."
                }
                $apiKey = "accesskey=$($keys[0]); secretkey=$($keys[1])"

                $reportList = Query-Tenable -TenableUrl $tenableUrl -ApiKey $apiKey -StartEpoch $startEpoch -EndEpoch $endEpoch

                if ($reportList) {
                    $successCount = 0
                    $failCount = 0
                    
                    foreach ($report in $reportList) {
                        if (Download-Report -Report $report -TenableUrl $tenableUrl -ApiKey $apiKey -ReportsFolder $reportsFolder) {
                            $successCount++
                        } else {
                            $failCount++
                        }
                    }
                    
                    Write-Log "Completed processing $centerName. Success: $successCount, Failed: $failCount" -Level "INFO"
                } else {
                    Write-Log "No reports found for Security Center: $centerName" -Level "WARNING"
                }
            } catch {
                Write-Log "Error processing $centerName: $_" -Level "ERROR"
                continue
            }
        }
    } catch {
        Write-Log "Fatal error: $_" -Level "ERROR"
    } finally {
        Write-Log "Script execution completed" -Level "INFO"
    }
}

Write-Output "Choose an option:"
Write-Output "1. Create/Update config.json (store encrypted API keys)"
Write-Output "2. Download reports using existing config.json"

$mode = Read-Host "Enter 1 or 2"
switch ($mode) {
    "1" { Invoke-ConfigSetup }
    "2" { Invoke-ReportDownload }
    default { Write-Output "Invalid choice. Exiting." }
}
