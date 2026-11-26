# 🛡️ CyberShield AI

**Advanced AI Cybersecurity & Threat Intelligence Platform**

CyberShield AI is a full-stack security platform that harnesses **Google Gemini** to detect phishing vectors, deepfake image tampering, compromised passwords, and malicious domains — all explained through **Explainable AI (XAI)** markdown reports that tell you *what* was found and *why*.

Built with Python Flask, SQLAlchemy, and the Google `google-genai` SDK, the platform replaces traditional rule-based detection with real-time machine intelligence and delivers printable security audit reports for every scan.

---

## ✨ Key Features

| Feature | Description |
| --- | --- |
| 🌐 **Website Security Audit** | Scans URLs for phishing heuristics, malware payloads, and domain reputation in real time. Verdict: **Risk Level** + **Malware Detection**. |
| 🖼️ **Deepfake & Image Forensics** | Detects AI-generated images via GAN artifacts, JPEG compression noise, ELA scores, lighting inconsistencies, and metadata analysis. |
| 📧 **Email Phishing Inspector** | Analyzes sender authenticity, SPF/DKIM/DMARC alignment, social-engineering urgency hooks, and suspicious links. |
| 🔑 **Password Strength & Breach Audit** | Computes mathematical bit entropy, detects dictionary/keyboard-walk patterns, and classifies risk. Only **anonymized metadata** is ever sent to Gemini. |
| 🛡️ **Personal Posture Advisor** | Evaluates a security questionnaire (MFA, backups, password hygiene) and returns an overall security score with actionable hardening steps. |
| 🤖 **AI Security Assistant** | Interactive chat node for immediate cybersecurity threat advice and incident response guidance. |
| 📄 **Printable XAI Reports** | Every scan generates a detailed, printable security report with transparent AI reasoning. |
| 📊 **Threat Telemetry Dashboard** | Live security score, threats intercepted, risk distribution, scan-type breakdown, and recent audit history. |
| 🔐 **Authentication & Roles** | JWT + bcrypt auth with session management, login history, and role-based access (`admin`, `analyst`, `user`). |

---

## 🧰 Tech Stack

| Layer | Technology |
| --- | --- |
| **Backend** | Python 3.10+ · Flask 3.1 · SQLAlchemy 2.0 |
| **AI Engine** | Google Gemini (`gemini-2.5-flash`) via `google-genai` SDK |
| **Database** | MySQL 8.0 (InnoDB, utf8mb4) with automatic **SQLite fallback** |
| **Authentication** | Flask-JWT-Extended · Flask-Bcrypt · PyJWT |
| **Frontend** | Jinja2 Templates · Vanilla JavaScript · CSS3 · Font Awesome |
| **Image Analysis** | Pillow · NumPy (forensic pre-processing) |
| **Testing** | Unittest-based suite covering API, auth, E2E, Gemini migration, and JSON repair |

---

## 📁 Project Structure

```
CyberShield_AI/
├── app.py                     # Flask entry point & REST API routes
├── config.py                  # Centralized app + Gemini configuration
├── gemini_service.py          # Legacy alias service (see services/gemini_service.py)
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
├── auth/                      # Authentication layer
│   ├── auth_routes.py
│   ├── decorators.py
│   ├── jwt_service.py
│   ├── password_service.py
│   └── permissions.py
├── database/                  # DB engine, sessions, schema & helpers
│   ├── __init__.py            # scan records, dashboard stats, report lookups
│   ├── base.py
│   ├── connection.py          # MySQL engine w/ SQLite fallback
│   ├── schema.sql             # Full MySQL 8.0 production schema (16 tables)
│   ├── seed.py
│   └── session.py
├── models/                    # SQLAlchemy models
│   ├── user.py, role.py, user_role.py
│   ├── user_session.py, refresh_token.py, login_history.py
│   ├── website_scan.py, email_scan.py, image_scan.py
│   ├── password_scan.py, security_audit.py, chat_message.py
│   ├── ai_report.py, audit_log.py, notification.py
│   └── system_setting.py, uploaded_file.py, api_key.py
├── repositories/              # Data-access repositories
│   ├── user_repository.py
│   ├── scan_repository.py
│   ├── report_repository.py
│   └── audit_repository.py
├── routes/                    # Blueprint-style route modules
│   ├── auth_routes.py, admin_routes.py, dashboard_routes.py
│   ├── website_routes.py, email_routes.py, image_routes.py
│   ├── password_routes.py, report_routes.py, chat_routes.py
├── schemas/                   # Request/response validation schemas
│   ├── auth_schema.py, scan_schema.py, report_schema.py
├── services/                  # Business & AI logic
│   ├── gemini_service.py      # Central Gemini client (retry, vision, chat, JSON)
│   ├── prompt_manager.py      # All Gemini prompt templates
│   ├── response_parser.py     # JSON validation & repair
│   ├── xai_formatter.py       # Explainable AI markdown formatters
│   ├── image_forensics.py     # Local image forensic pre-processing
│   ├── image_service.py, email_service.py, password_service.py
│   ├── website_service.py, report_service.py, dashboard_service.py
│   └── prompt_manager.py
├── static/
│   ├── css/styles.css         # App styling
│   └── js/main.js             # Frontend logic & markdown renderer
├── templates/                 # Jinja2 templates
│   ├── landing.html           # Marketing/landing page
│   ├── index.html             # Dashboard
│   ├── profile.html           # User profile
│   └── report.html            # Printable security report
├── tests/                     # Test suite
│   ├── test_api.py, test_auth.py, test_e2e.py
│   ├── test_scans.py, test_json_repair.py
│   └── test_gemini_migration.py
├── utils/                     # Helpers, constants, logging, security, validators
├── certs/                     # CA certificates
├── uploads/                   # Uploaded image scans
└── instance/                  # Runtime instance data (ignored by git)
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **Google Gemini API key** — get one from [Google AI Studio](https://aistudio.google.com/)
- **MySQL 8.0** *(optional — the app automatically falls back to SQLite if MySQL is unavailable)*

### 1. Clone & Set Up Virtual Environment

```bash
git clone <your-repo-url>
cd CyberShield_AI

# Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# macOS / Linux
# source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the template and fill in your values:

```bash
cp .env.example .env
```

At minimum, set your Gemini API key:

```ini
# Gemini AI
GEMINI_API_KEY=your_google_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash

# Flask
SECRET_KEY=change-me
JWT_SECRET_KEY=change-me

# Database (MySQL — optional; SQLite fallback is automatic)
# DATABASE_URL=mysql+pymysql://user:password@localhost:3306/cybershield_ai
# DB_USER=root
# DB_PASSWORD=your_password
# DB_HOST=localhost
# DB_PORT=3306
# DB_NAME=cybershield_ai
```

### 4. Initialize the Database

For **MySQL** (production), run the schema script once:

```bash
mysql -u root -p < database/schema.sql
```

For **SQLite** (default), tables are created automatically on first run via `database.init_db()`.

### 5. Run the Application

```bash
python app.py
```

Then open your browser and navigate to **http://localhost:5000**

---

## ⚙️ Configuration Reference

All settings are read from environment variables (see `config.py`):

| Variable | Default | Description |
| --- | --- | --- |
| `SECRET_KEY` | `cybershield-secret-key-1337` | Flask session signing key |
| `JWT_SECRET_KEY` | `change-this-jwt-secret` | JWT signing key |
| `DATABASE_URL` | `sqlite:///cybershield.db` | SQLAlchemy DB URI (fallback) |
| `DB_USER` / `DB_PASSWORD` | — | MySQL credentials (enables MySQL mode) |
| `DB_HOST` / `DB_PORT` | `localhost` / `3306` | MySQL host & port |
| `DB_NAME` | `cybershield_ai` | MySQL database name |
| `UPLOAD_FOLDER` | `uploads` | Image upload directory |
| `MAX_CONTENT_LENGTH` | `16MB` | Max upload size |
| `GEMINI_API_KEY` | — | **Required** — Google Gemini API key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model to use |
| `TEMPERATURE` | `0.2` | AI sampling temperature |
| `MAX_OUTPUT_TOKENS` | `8192` | Max AI output length |
| `TIMEOUT` | `60` | Gemini request timeout (seconds) |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Create a new user account |
| `POST` | `/api/auth/login` | Authenticate and receive a JWT |
| `POST` | `/api/auth/logout` | Invalidate session |
| `GET` | `/api/auth/me` | Fetch the current authenticated user |
| `POST` | `/api/check-website` | Run a website security audit `{ "url": "..." }` |
| `POST` | `/api/check-image` | Upload an image for deepfake/forensic analysis |
| `POST` | `/api/check-email` | Analyze an email for phishing `{ "sender": "...", "body": "..." }` |
| `POST` | `/api/check-password` | Audit password strength `{ "password": "..." }` |
| `POST` | `/api/get-advice` | Run the personal security posture questionnaire |
| `POST` | `/api/chat` | Chat with the AI security assistant |
| `GET` | `/api/stats` | Dashboard telemetry metrics |
| `GET` | `/api/reports/<scan_id>?type=<scan_type>` | Renders a printable security report |
| `POST` | `/api/clear-history` | Clear scan history for the active user |

---

## 🗄️ Database Schema

The MySQL schema (`database/schema.sql`) defines **16 InnoDB tables** with utf8mb4 encoding:

1. `users` — accounts, password hashes, login state
2. `roles` — `admin`, `analyst`, `user`
3. `user_roles` — many-to-many user/role mapping
4. `user_sessions` — active session tokens
5. `refresh_tokens` — JWT refresh token storage
6. `login_history` — success/failure login attempts
7. `website_scans` — URL/domain audit results
8. `email_scans` — phishing inspection results
9. `image_scans` — deepfake/forensic results
10. `password_scans` — strength/entropy/breach results
11. `security_audits` — posture advisor questionnaire results
12. `chat_messages` — AI assistant conversation history
13. `ai_reports` — printable XAI security reports
14. `audit_logs` — system audit trail
15. `notifications` — user notifications
16. `system_settings` — key/value system configuration

> All scan tables persist a JSON `result_json` payload plus an `explanation_markdown` XAI report for full transparency and reproducible reports.

---

## 🧪 Testing

Run the full test suite:

```bash
python -m unittest discover -s tests -v
```

Or run individual suites:

```bash
python tests/test_gemini_migration.py   # Gemini + XAI migration tests
python tests/test_json_repair.py        # JSON response repair tests
python tests/test_auth.py               # Authentication tests
python tests/test_api.py                # API endpoint tests
python tests/test_scans.py              # Scan pipeline tests
python tests/test_e2e.py                # End-to-end tests
```

---

## 🔒 How It Works

1. **Prompt Building** — `services/prompt_manager.py` constructs structured prompts (passwords are sent only as anonymized metadata).
2. **Gemini Inference** — `services/gemini_service.py` calls the Gemini API with automatic retries, exponential backoff, and JSON enforcement.
3. **Response Parsing** — `services/response_parser.py` validates and repairs the model's JSON payload.
4. **XAI Formatting** — `services/xai_formatter.py` guarantees every report includes a `### 🛡️ Explainable AI (XAI) Assessment` section with short "label → why" bullets.
5. **Persistence** — Results are stored in MySQL (or SQLite) and linked to a printable `AIReport`.
6. **Presentation** — The dashboard, report page, and markdown renderer display the results with full transparency.

---

## 📄 License

This project is provided for educational and research purposes. Use it responsibly and only scan resources you own or are authorized to test.

---

## 🙏 Acknowledgements

- [Google Gemini API](https://aistudio.google.com/) — AI inference engine
- [Flask](https://flask.palletsprojects.com/) — web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) — ORM & database toolkit
- [Pillow](https://python-pillow.org/) / [NumPy](https://numpy.org/) — image forensics

