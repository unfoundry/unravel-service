# Unravel Service

Unravel Engine (as a service): Automated & Human-in-the-Loop Headless Ingestion, Cleaning, and Normalization of tabular data.

Companion backend service providing:
- **XLSX Decryption Gateway**: Securely decrypt password-protected Microsoft Excel spreadsheets (`msoffcrypto-tool`) via streaming RAM buffers.
- **Headless Ingestion Pipeline**: Server-side layout translation, column mapping, regex/NHS/type validation rules, multi-step transformations, and computed fields.
- **Admin Dashboard**: Bootswatch Lumen management portal with system telemetry, schema configuration management, audit log inspection, and purging.
- **REST APIs**: Automated dataset processing, status health checks, and metrics.

---

## 🚀 Quickstart

### 1. Local Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 unravel_service.py
```
Service runs at `http://localhost:8000`.

### 2. Docker & Docker Compose
```bash
docker compose up -d --build
```

---

## ⚙️ Configuration (.env)

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `8000` | HTTP listening port |
| `ADMIN_USERNAME` | `admin` | Admin dashboard login |
| `ADMIN_PASSWORD` | `unraveladmin` | Admin dashboard password |
| `SECRET_KEY` | `unravel-secret-key-...` | Session cookie signing key |
| `RATE_LIMIT_PER_MINUTE` | `60` | Ingestion API rate limit |

---

## 📚 Endpoints Overview

- `GET /` — Service status and health probe
- `GET /admin` — Interactive admin dashboard (schemas, metrics, logs)
- `POST /api/decrypt` — Decrypt password-protected XLSX file in-memory
- `POST /api/process` — Headless schema-based dataset cleaning & validation
- `GET /metrics` — Telemetry and usage stats
