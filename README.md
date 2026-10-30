# WE CARE — Industrial Water Treatment & Sales CRM Platform

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Koppulasandeep18/wecaree)

A complete, production-ready full-stack web application for **WE CARE** industrial and domestic water treatment solutions, integrated with a high-performance Sales CRM, real-time analytics, and automated lead ingestion.

---

## 🚀 One-Click Cloud Deployment

### Option 1: Deploy to Render (Recommended — Free & Persistent)
1. Click the **[Deploy to Render](https://render.com/deploy?repo=https://github.com/Koppulasandeep18/wecaree)** button above, or go to [dashboard.render.com](https://dashboard.render.com).
2. Click **New +** → **Blueprint** and select this repository: `Koppulasandeep18/wecaree`.
3. Render automatically reads [`render.yaml`](render.yaml) and attaches a persistent 1 GB disk to `/app/data` so all CRM records, leads, and customer profiles persist permanently.
4. Click **Apply**. Your live HTTPS URL will be active in ~60 seconds!

### Option 2: Deploy to Railway
1. Go to [railway.com](https://railway.com) and log in with GitHub.
2. Click **New Project** → **Deploy from GitHub repo** → select `wecaree`.
3. In Settings, add a Volume mounted at `/app/data` for SQLite persistence.
4. Click **Generate Domain**.

---

## 🛠️ Tech Stack & Architecture

- **Backend:** Python 3 standard library with `ThreadingHTTPServer` (concurrent, non-blocking asynchronous request handling).
- **Frontend:** Responsive vanilla JavaScript SPA with 17 public routes, glass-style sticky navbar, and 21 sequential homepage sections.
- **Database:** SQLite 3 in Write-Ahead Logging (`WAL`) mode with `busy_timeout = 30000`, foreign key enforcement, and indexed relational schema.
- **Security:**
  - PBKDF2 password hashing with cryptographically secure random salts.
  - Role-Based Access Control (RBAC): `SUPER_ADMIN`, `SALES_MANAGER`, `SALES_EXECUTIVE`.
  - Sensitive file blocking (`.db`, `.py`, `.log`, `.bak` return HTTP 403).
  - In-memory sliding window rate limiting on authentication attempts (HTTP 429).
  - Formula injection escaping on CSV exports.
  - Non-blocking asynchronous SMTP notification dispatch.

---

## 🔑 Default Admin CRM Credentials

Navigate to `/admin` on your deployed domain:

| Role | Username | Password |
| :--- | :--- | :--- |
| **Super Admin** | `admin` | `Admin@123` |
| **Sales Manager** | `manager` | `Manager@123` |
| **Sales Executive** | `executive` | `Executive@123` |

---

## 💻 Local Development

Run the server locally with Python 3:

```bash
# Clone the repository
git clone https://github.com/Koppulasandeep18/wecaree.git
cd wecaree

# Start the application
python server.py 8080
```

Open [http://localhost:8080](http://localhost:8080) for the public website and [http://localhost:8080/admin](http://localhost:8080/admin) for the sales CRM.

---

## 🐳 Docker Deployment

Run with Docker Compose:

```bash
docker compose up -d
```
