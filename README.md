# ThreatSpectra

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-000000?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-Permission--First-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-2ea44f)

ThreatSpectra is a full-stack phishing detection platform that analyzes multiple attack surfaces in one place: URLs, emails, SMS messages, and QR codes. It combines machine learning predictions with practical rule-based checks and provides a modern frontend for fast security screening.

## Overview

ThreatSpectra helps users identify suspicious content before they click links, respond to messages, or share sensitive data.

Core capabilities:
- URL phishing detection
- Email phishing detection
- SMS phishing detection
- QR-code URL extraction and risk detection
- Contact form with SMTP delivery

## Features

Frontend:
- Multi-mode scanner interface (URL, Email, SMS, QR)
- Real-time result cards with confidence values
- Quick sample inputs for testing
- Responsive cybersecurity-themed UI

Backend:
- Flask API with CORS enabled
- Random Forest-based URL detection pipeline
- Feature-based email detection pipeline
- TF-IDF based SMS detection pipeline
- QR decoding with `zxing-cpp` and `pyzbar` fallback
- Contact endpoint with SMTP forwarding

## Project Structure

```text
.
|- app.py
|- index.html
|- .env.example
|- requirements.txt
|- runtime.txt
|- email/
|  |- email_features.py
|  |- email_predict.py
|  |- email_rules.py
|- url/
|  |- url_features.py
|  |- url_predict.py
|  |- url_rules.py
|- sms/
|  |- sms_predict.py
|- models/
|  |- load_models.py
|- utils/
|  |- helpers.py
|  |- text_utils.py
|- static/
|  |- css/style.css
|  |- js/script.js
|  |- images/
|- extension/
|  |- manifest.json
|  |- background.js
|  |- content.js
|  |- popup.html
|  |- popup.css
|  |- popup.js
|  |- assets/
|  |- dist/
|- website_detection/
|  |- Phishing_website_detection.ipynb
|  |- phishing_model_complete.pkl
|- email_detection/
|  |- Model_Training.ipynb
|  |- email_phishing_model.pkl
|- sms_detection/
|  |- SMS_phishing_detection.ipynb
|  |- sms_phishing_model.pkl
```

## API Endpoints

### `GET /`
Serves the main ThreatSpectra webpage.

### `POST /predict`
Analyzes URL phishing risk.

Request:
```json
{
  "url": "https://example.com"
}
```

### `POST /predict_email`
Analyzes email phishing risk.

Request:
```json
{
  "email": "Paste full email content here"
}
```

### `POST /predict/email`
Legacy-compatible email route.

Request:
```json
{
  "text": "Paste full email content here"
}
```

### `POST /predict/sms`
Analyzes SMS phishing risk.

Request:
```json
{
  "text": "Your package is on hold, verify now..."
}
```

### `POST /predict-qr`
Accepts QR image upload (`qr_image`) and analyzes the decoded URL.

### `POST /contact/send`
Sends website contact form submissions to the configured inbox.

Request:
```json
{
  "name": "Your Name",
  "email": "you@example.com",
  "message": "Hello"
}
```

## Local Setup

### Prerequisites
- Python 3.9+
- `pip`

### Install and Run (Windows PowerShell)

```powershell
cd "C:\Users\KRISH\OneDrive\Desktop\Cyber Security Projects\ThreatSpectra"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open:
- `http://127.0.0.1:5000`
- `http://localhost:5000`

## Browser Extension

ThreatSpectra includes a browser extension in `extension/`.

Capabilities:
- Automatically scans visited websites via `POST /predict`
- Shows top-right on-page alert: `Safe` or `Unsafe`
- Supports manual checks in popup: URL, QR, Email, SMS
- Includes scan history with delete and clear controls

History disclaimer:
- Only the latest 15 checks are stored
- Older entries are deleted automatically

### 1) Start API server

```powershell
python app.py
```

Keep the server running at `http://127.0.0.1:5000`.

### 2) Load extension in Chrome / Edge / Brave / Opera

1. Open extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select folder: `ThreatSpectra/extension`

### 3) Load extension in Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click `Load Temporary Add-on`
3. Select `ThreatSpectra/extension/manifest.json`

### 4) Use extension

1. Click the extension icon
2. Keep `Automatic top-right alert` ON for auto site alerts
3. Open or refresh a website tab to trigger scanning
4. Use popup tabs for manual URL, QR, Email, and SMS scans
5. Manage records from the History tab

If popup alerts do not appear:
- Confirm Flask server is running
- Test on normal `http/https` pages (not browser internal pages)
- Refresh the tab after enabling the extension

## SMTP Configuration (Contact Form)

Set environment variables (or define them in a local `.env` file):

```powershell
$env:CONTACT_SMTP_HOST="smtp.gmail.com"
$env:CONTACT_SMTP_PORT="587"
$env:CONTACT_SMTP_USERNAME="your-email@gmail.com"
$env:CONTACT_SMTP_PASSWORD="your-app-password"
$env:CONTACT_TO_EMAIL="your-email@gmail.com"
$env:CONTACT_FROM_EMAIL="your-email@gmail.com"
$env:CONTACT_SMTP_USE_TLS="true"
```

Restart the Flask server after updating variables.

## Code Health Check

Use the same virtual environment and run:

```powershell
# 1) Syntax check all Python files
python -m compileall -q .

# 2) Runtime smoke check (imports app + model loaders)
python -c "import app; print('APP_IMPORT_OK')"
```

Expected:
- `compileall` exits with no errors
- Import smoke test prints `APP_IMPORT_OK`

## Tech Stack

- Flask
- Flask-CORS
- scikit-learn
- pandas
- numpy
- requests
- BeautifulSoup
- Pillow
- zxing-cpp
- pyzbar
- HTML, CSS, JavaScript, Bootstrap, AOS

## Contribution Guide

Contributions are welcome.

How to contribute:
1. Open an issue describing your change.
2. Request permission before using, modifying, distributing, or deploying this project.
3. Fork the repository and create a feature branch.
4. Submit a pull request with clear notes and test details.

By contributing, you agree your contributions may be used under this repository license.

## License

This repository uses a custom permission-first license:
- You must ask the owner for permission before using, distributing, or deploying this project.
- Contributions are allowed via pull requests.

See [LICENSE](LICENSE) for complete terms.

## Maintainer

- Name: Krish
- GitHub: https://github.com/krishyadav90
- LinkedIn: https://www.linkedin.com/in/krish-yadav-aba86a2bb/

## Disclaimer

ThreatSpectra provides security predictions, not absolute guarantees. Validate high-risk outcomes with additional security checks before taking action.
