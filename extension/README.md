# ThreatSpectra Browser Extension

This extension checks websites with your ThreatSpectra API and shows a top-right on-page alert:
- Safe
- Unsafe

It also includes manual scanners in popup for:
- URL
- QR image
- Email text
- SMS text

It stores scan history with per-item delete and clear-all controls.

## Files
- manifest.json
- background.js
- content.js
- popup.html
- popup.css
- popup.js

## Run
1. Start API server from project root:
   - python app.py
2. Load `extension/` as unpacked extension in browser.
3. Keep popup toggle ON in extension popup for automatic alerts.
4. Use manual scan sections (URL/QR/Email/SMS) as needed.
5. Manage history entries from the Visit History section.

## Build ZIP
Run in PowerShell:

```powershell
cd extension
.\build-extension.ps1
```

Output ZIP:
- extension/dist/threatspectra-extension.zip
