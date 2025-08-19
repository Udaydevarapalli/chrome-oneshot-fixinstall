# Chrome One-Shot Fix & Install (Public Domain)

A one-shot PowerShell script that:
- Downloads the official Chrome Enterprise MSI (x64/x86)
- Verifies Authenticode signature (Google LLC)
- Cleans common remnants, resets Windows Installer, ensures services
- Installs Chrome silently with full logging (+ optional repair retry)
- Extracts a "Return value 3" snippet for quick triage

## Usage (Run as Administrator)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Chrome-OneShot-FixInstall.ps1
