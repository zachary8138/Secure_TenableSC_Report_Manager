# Tenable Reporting (PowerShell)

Helper script to **securely store Tenable.sc API keys** (encrypted at rest) and **download finished PDF/CSV reports** from one or more Tenable.sc (“Security Center”) instances into a timestamped output folder.

## What it does

- **Mode 1**: Create/update `config.json` with one or more Tenable.sc entries:
  - `url`: Tenable.sc base URL (must be **HTTPS**)
  - `encrypted_key`: encrypted `accessKey;secretKey` bundle
- **Mode 2**: Prompt for a time window, then:
  - queries `/rest/report?fields=id,name,type,finishTime`
  - filters to report `type` in `pdf`/`csv` with `finishTime` within the window
  - downloads each match via `/rest/report/{id}/download`

## Requirements

- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+
- **Network access** to your Tenable.sc instance(s)
- **Environment variable `FERNET`**: base64-encoded **32 bytes** (256-bit key)

## Security model (read this)

- API keys are **encrypted for storage at rest**, but are **decrypted in memory** during execution.
- Encryption uses **AES-CBC + HMAC-SHA256 (encrypt-then-MAC)**.
- Keep `config.json` and generated logs in a **protected directory**.
- Use **least-privilege** Tenable.sc API keys (report listing + download only).

## Quick start

### 1) Set the encryption key

You must set `FERNET` to base64-encoded 32 bytes.

Example generators:

```bash
# Linux/macOS (bash)
export FERNET="$(python3 - <<'PY'
import os,base64
print(base64.b64encode(os.urandom(32)).decode())
PY
)"
```

```powershell
# PowerShell
$env:FERNET = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

### 2) Run the script

```powershell
pwsh ./Tenable_Reporting.ps1
# or (Windows PowerShell)
powershell.exe -ExecutionPolicy Bypass -File .\Tenable_Reporting.ps1
```

### 3) Choose a mode

- **1**: Create/Update `config.json` (prompts for URL, access key, secret key)
- **2**: Download reports (prompts for start/end date)

## Usage details

### Mode 1: Create/Update config

- Prompts you to add one or more “Security Centers” by name (e.g., `acas1`)
- Enforces that URLs are valid **HTTPS**
- Stores the encrypted key bundle into `config.json`
- Attempts to restrict file permissions:
  - **Linux**: `chmod 600 config.json` (best-effort)
  - **Windows**: ACL tightened to current user (best-effort)

### Mode 2: Download reports

Prompts for:

- **Start date**: `YYYY-MM-DD HH:MM`
- **End date**: `YYYY-MM-DD HH:MM`

Creates an output folder in the **current working directory**:

- `<yyyy-MM-dd_HH-mm>_Tenable-Reports/`
  - `reports/` (downloaded `.pdf`/`.csv`)
  - `<foldername>.log` (execution log)

Report file names are sanitized to remove invalid filename characters.

## `config.json` format

Example:

```json
{
  "acas1": {
    "url": "https://tenable.example",
    "encrypted_key": "BASE64_BLOB..."
  },
  "acas2": {
    "url": "https://tenable2.example",
    "encrypted_key": "BASE64_BLOB..."
  }
}
```

## Troubleshooting

- **“FERNET environment variable is not set / not valid base64 / must decode to 32 bytes”**
  - Regenerate and export a base64 key that decodes to exactly **32 bytes**.
- **“URL must be a valid HTTPS URL”**
  - Ensure the Tenable.sc URL starts with `https://` and is well-formed.
- **HMAC/integrity check failures**
  - Usually means `FERNET` changed since `config.json` was created, or `config.json` was corrupted/edited.
  - Restore the original `FERNET` or recreate `config.json` (Mode 1).
- **No reports found**
  - Confirm the time window aligns with Tenable.sc `finishTime` values and that reports are of type `pdf` or `csv`.

## Notes

- The script uses `Invoke-RestMethod` with retries (`MaxRetries`, `RetryDelay`) and `TimeoutSeconds`.
- Secrets are not intentionally printed to the console/logs. (script is written to avoid logging your Access Key / Secret Key (or the decrypted ```accesskey=...; secretkey=...``` header) on purpose—so normal status/error messages shouldn’t contain secrets.
