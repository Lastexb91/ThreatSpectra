# ThreatSpectra

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-000000?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-Permission--First-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-2ea44f)

ThreatSpectra is a full-stack phishing detection website that analyzes multiple attack surfaces in one place: URLs, emails, SMS messages, and QR codes. It combines machine learning predictions with practical safety heuristics and provides a modern, interactive frontend built for real-time security checks.

## Overview

ThreatSpectra helps users quickly identify suspicious content before they click, reply, or share sensitive information.

Core capabilities:
- URL phishing analysis
- Email text phishing analysis
- SMS phishing analysis
- QR-image scanning and phishing evaluation
- Contact form with SMTP delivery to the project owner

## Website Features

Frontend highlights:
- Multi-mode scanner interface (URL, Email, SMS, QR)
- Real-time result cards with confidence scores
- Advanced quick examples for testing inputs
- Policy details panel in footer
- Responsive cybersecurity-themed UI

Backend highlights:
- Flask API with CORS enabled
- Random Forest-based URL model pipeline
- Feature-based email phishing model pipeline
- TF-IDF based SMS phishing model pipeline
- QR decoding with zxing-cpp and pyzbar fallback, plus Pillow-based preprocessing
- Contact endpoint with SMTP mail forwarding

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
Serves the main ThreatSpectra web page.

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
Legacy-compatible email route used by frontend.

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
Accepts QR image upload (`qr_image`) and analyzes decoded URL.

### `POST /contact/send`
Sends website contact form submissions to configured inbox.

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
- pip

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
- or `http://localhost:5000`

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

Then restart the Flask server.

## Code Health Check (Re-run Anytime)

Use the same virtual environment and run:

```powershell
# 1) Syntax check all Python files
python -m compileall -q .

# 2) Runtime smoke check (imports app + model loaders)
python -c "import app; print('APP_IMPORT_OK')"
```

Expected result:
- `compileall` returns with no errors
- app import prints `APP_IMPORT_OK`

Latest local check status (March 29, 2026):
- `compileall`: passed
- app import smoke test: passed

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
2. Ask for permission to use/modify this project before distributing or deploying it.
3. Fork the repository and create a feature branch.
4. Submit a pull request with clear notes and test details.

By contributing, you agree that your contribution can be used in this project under the repository license.

## License

This repository uses a custom permission-first license:
- You must ask the owner for permission before using, distributing, or deploying this project.
- Contributions are allowed and encouraged via pull requests.

See [LICENSE](LICENSE) for full terms.

## Maintainer

- Name: Krish
- GitHub: https://github.com/krishyadav90
- LinkedIn: https://www.linkedin.com/in/krish-yadav-aba86a2bb/

## Disclaimer

ThreatSpectra provides security predictions, not legal or absolute guarantees. Always validate high-risk outcomes with additional security checks before taking action.
