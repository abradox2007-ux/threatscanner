# ThreatScan — Universal Spam & Threat Detection

A full-stack web application that scans **text/email**, **images**, and **URLs**
for phishing, spam, and malware indicators — with a live threat-score dashboard.

---

## Quick Start (Local — No Docker)

**Requirements:** Python 3.10 or newer

```bash
# 1. Unzip the project, open a terminal in the folder
# 2. Run:

# macOS / Linux
bash run.sh

# Windows
run.bat
```

Open **http://localhost:8000** in your browser. That's it.

---

## Docker Start (Production-ready)

```bash
cd docker
cp ../.env.example ../.env   # add API keys if you have them
docker compose up --build
```

Open **http://localhost** (port 80 via Nginx).

---

## Adding API Keys (Optional but Recommended)

The app works fully without any API keys using heuristic analysis.
Adding keys unlocks cloud threat-intelligence checks:

Edit `.env`:

```
SAFE_BROWSING_API_KEY=your_key_here   # https://console.cloud.google.com
VIRUSTOTAL_API_KEY=your_key_here      # https://www.virustotal.com/gui/join-us
```

Restart the server after saving.

---

## Project Structure

```
threatscanner/
├── backend/
│   ├── main.py                  ← FastAPI app + static file serving
│   ├── config.py                ← Env var loader
│   ├── routers/
│   │   ├── text_scan.py         ← POST /api/scan/text
│   │   ├── image_scan.py        ← POST /api/scan/image
│   │   └── url_scan.py          ← POST /api/scan/url
│   ├── services/
│   │   ├── nlp_engine.py        ← 40+ spam/phishing heuristics
│   │   ├── ocr_engine.py        ← EasyOCR + EXIF metadata analysis
│   │   ├── url_engine.py        ← Safe Browsing, VT, WHOIS, SSL
│   │   ├── risk_scorer.py       ← Weighted 0–100 threat score
│   │   └── ssrf_guard.py        ← Blocks private/internal IPs
│   ├── middleware/
│   │   └── rate_limiter.py      ← Sliding-window (Redis or in-memory)
│   └── models/
│       └── schemas.py           ← Pydantic request/response models
├── frontend/
│   ├── index.html               ← Dashboard UI
│   ├── css/style.css
│   └── js/app.js
├── docker/
│   ├── docker-compose.yml
│   └── Dockerfile.api
├── nginx/nginx.conf
├── requirements.txt
├── .env.example
├── run.sh                       ← macOS/Linux one-click start
└── run.bat                      ← Windows one-click start
```

---

## Features

| Feature | Details |
|---|---|
| Text/Email scan | Urgency language, phishing phrases, credential harvesting, spoofed headers |
| Image scan | EasyOCR text extraction, EXIF metadata anomaly detection |
| URL scan | SSRF guard, SSL check, domain age (WHOIS), Google Safe Browsing, VirusTotal |
| Risk meter | Animated 0–100% threat score with Green / Yellow / Red levels |
| Rate limiting | 30 req/min per IP (Redis or in-memory fallback) |
| Input sanitization | Pydantic v2 schemas + bleach HTML stripping on all inputs |
| SSRF protection | Blocks all RFC-1918, link-local, and cloud metadata IPs |

---

## API Endpoints

```
POST /api/scan/text
  Body: { "text": "..." }

POST /api/scan/image
  Body: multipart/form-data  field: file (image/*)

POST /api/scan/url
  Body: { "url": "https://..." }

GET  /health
```

All endpoints return:
```json
{
  "score": 72,
  "level": "dangerous",
  "summary": "High-confidence threat...",
  "signals": [
    { "label": "Phishing language detected", "category": "phishing", "weight": 0.5 }
  ],
  "extracted_text": null,
  "scan_type": "text"
}
```

---

## Security Notes

- **SSRF guard** resolves every user-supplied URL to its IP before any request is made, blocking all private/internal ranges including AWS IMDS (169.254.169.254).
- **Rate limiter** uses a Redis sliding-window; falls back to in-memory automatically.
- **Input sanitization** strips HTML/JS via `bleach` before any NLP processing.
- **CORS** is set to `*` for local dev — restrict `allow_origins` to your domain before going public.
- **Nginx** adds `X-Frame-Options`, `X-Content-Type-Options`, and a strict `Content-Security-Policy` in the Docker setup.
