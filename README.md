# Data Leak Guardian

## Problem Statement

Documents such as identity forms, bank records, and contact sheets can contain sensitive personal information. It is easy to overlook these values when reviewing a document manually, especially when the document is an image or scanned PDF.

## Objective

Data Leak Guardian is a small local web application that extracts text from PDF and image uploads, detects selected sensitive-data patterns, calculates a deterministic privacy-risk score, and displays masked findings with an explainable summary.

## Features

- Upload PDF, PNG, JPG, or JPEG files up to 5 MB.
- Extract selectable PDF text and use OCR for scanned PDFs and images.
- Detect eight supported sensitive-data categories with deterministic patterns and contextual checks.
- Display masked findings, risk score, risk level, score contributions, and explanations.
- Generate downloadable PDF privacy reports.
- Save scan metadata and masked results in SQLite.
- View dashboard totals, risk-level counts, recent scans, and scan history.
- Reopen previous results, download their reports, and delete a scan with its associated artifacts.
- Register and sign in with a password hash; scans and reports are scoped to the owning account.
- Protect state-changing forms with CSRF tokens and log out by clearing the session.

## System Workflow

1. Register or sign in to an account, then select a PDF or image in the upload page.
2. The application validates the file extension, size, and basic file signature, then saves it under a generated filename in private instance storage.
3. Text is extracted from the PDF or OCR is applied to images/scanned PDFs.
4. Rule-based detectors find supported data patterns. Matching values are masked before being stored or shown.
5. The scoring service deduplicates identical category/value matches, adds category weights, and caps the total at 100.
6. The result page and a masked PDF report are produced; scan metadata and masked findings are saved to SQLite.
7. Use Dashboard or Scan History to review, reopen, download, or delete completed scans.

## Technology Stack

- Python 3.12 (the project was developed and tested with Python 3.12)
- Flask 3.0.3, Flask-WTF 1.2.2, and Werkzeug 3.0.3
- SQLite
- PyMuPDF 1.28.2
- Pillow 12.3.0 and pytesseract 0.3.13
- Tesseract OCR (external system executable, needed for OCR)
- ReportLab 5.0.1
- Bootstrap 5.3.3 via CDN
- pytest 8.3.3

## Architecture

The application uses a small Flask app factory and a service-oriented pipeline:

```text
Browser
  -> Session authentication and CSRF validation
     -> Flask routes
     -> Upload validation/storage
     -> Text extraction and OCR
     -> Sensitive-data detection
     -> Risk scoring
     -> Masked result and PDF report
     -> SQLite scan history
```

The detector, scorer, extraction service, report generator, and masking utility are separate modules. SQLite stores user accounts and document metadata with an owner ID; scan results contain masked findings only. Uploaded source files and reports are stored in the application's private `instance/` directory. The database is `database/app.db`, and `database/schema.sql` defines the base schema. Existing databases receive additive column migrations during app initialization; older scans without an owner remain inaccessible to user accounts.

## Folder Structure

```text
app/
  routes/                 Flask web routes
  services/               Upload, extraction, detection, scoring, reports
  static/css/             Shared application styles
  templates/              Upload, result, dashboard, history, login, and registration pages
  utils/                  Shared masking utility
database/
  schema.sql              SQLite base schema
instance/
  uploads/                Private uploaded documents (created at runtime)
  reports/                Private generated PDF reports (created at runtime)
tests/                    pytest test suite
requirements.txt           Python dependencies
run.py                     Development entry point
```

## Installation Requirements

- Python 3.12 recommended.
- Tesseract OCR installed for image and scanned-PDF OCR. Text-based PDFs can be read without OCR, but OCR fallback requires Tesseract.
- Network access to load Bootstrap CSS from its CDN, unless the stylesheet is served locally instead.

### Install Tesseract

On Windows, install the Tesseract OCR engine. The application recognizes the standard path `C:\Program Files\Tesseract-OCR\tesseract.exe` when present; otherwise, make the `tesseract` executable available on `PATH`.

On Debian/Ubuntu, install the system package with:

```sh
sudo apt install tesseract-ocr
```

On macOS with Homebrew:

```sh
brew install tesseract
```

## Python Environment Setup

From the project root on Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS/Linux:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the Application

From the project root with the virtual environment active:

```powershell
$env:FLASK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python run.py
```

Set `FLASK_SECRET_KEY` to a stable, randomly generated value and keep it private; use a secret manager/environment configuration outside local development. Open `http://127.0.0.1:5000/` and register an account. The built-in Flask server is for local development and should not be exposed directly to the public internet.

## Run Tests

```powershell
python -m pytest -q
```

The suite covers extraction/OCR, detection, risk scoring, report generation, integration flows, scan history, authentication, ownership, CSRF, and security behavior.

## Detection Categories

The rule-based detector currently supports:

- Aadhaar: 12-digit identifier, with Aadhaar/UID context
- PAN: Indian PAN format
- Bank account number: 9–18 digits with financial-account context
- IFSC: Indian IFSC format
- Phone: supported Indian phone-number formats with contact context in applicable cases
- Email: conventional email address pattern
- Date of birth: valid supported date formats with birth/DOB context
- PIN/postal code: six digits with PIN/postal/ZIP context

These are pattern matches, not authoritative validation of identity or account records. Detection can miss unusual formats or produce false positives.

## Risk Scoring Methodology

For each distinct `(category, matched value)`, the scorer adds the configured category weight. Identical category/value pairs are counted once. The final score is capped at 100.

| Category | Weight |
| --- | ---: |
| Aadhaar | 30 |
| PAN | 20 |
| Bank account | 25 |
| IFSC | 10 |
| Phone | 15 |
| Email | 10 |
| Date of birth | 15 |
| PIN/postal code | 20 |

| Score | Risk level |
| ---: | --- |
| 0–24 | Low |
| 25–49 | Moderate |
| 50–74 | High |
| 75–100 | Critical |

The result includes category contributions and a text explanation of detected categories.

## Privacy and Security Features

- Uploads are limited to 5 MB and checked against allowed extensions and basic file signatures.
- Uploaded documents receive random filenames and are stored outside Flask's public static directory.
- Reports are stored privately and can be downloaded only through a matching completed scan record.
- Scan IDs are scoped to the authenticated owner for viewing, report download, and deletion; arbitrary filenames are not accepted by those routes.
- Passwords are stored as Werkzeug password hashes, not plaintext.
- Flask-WTF validates CSRF tokens on state-changing forms, including login, registration, upload, logout, and deletion.
- Session cookies are HTTP-only and use SameSite=Lax.
- Sensitive finding values are masked in the UI, PDF report, and persisted scan findings. Extracted document text and raw finding values are not stored in the scan history.
- Deletion removes the selected scan record and its linked private artifacts; matching legacy copies are also removed when present.
- Users can only view scans associated with their own account. Unowned legacy scans are not shown to authenticated users.

## Known Limitations

- The detector is deterministic and limited to the eight listed categories and supported formats; it does not use AI/NLP.
- OCR accuracy depends on image quality, language, and Tesseract configuration. The current OCR setup uses Tesseract's default language data.
- Risk weights are illustrative project rules, not a compliance certification or substitute for expert review.
- There is no email verification, password reset, multi-factor authentication, or login rate limiting.
- Accounts use a minimum eight-character password length; additional password-strength requirements are not enforced.
- Use a stable secret key and a production WSGI server before deployment beyond local use.
- Bootstrap is loaded from a CDN, so styling may be unavailable without network access.
