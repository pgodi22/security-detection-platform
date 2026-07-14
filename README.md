# Security Detection Platform

## 1. Overview

A SOC triage console. External systems POST security events to an ingestion
API; each event is matched against admin-defined signatures, and a match
becomes a prioritized **Detection** that analysts claim, investigate, and
close. Admins manage the customers and signatures driving that matching;
analysts work the detection queue; read-only users get full visibility with
no write access. Server-rendered FastAPI + Jinja2 app with JWT cookie auth
and role-based access control.

## 2. Running Locally

**Prerequisites:**

- Python 3.12
- PostgreSQL 14+ (Ubuntu: `sudo apt install postgresql postgresql-contrib -y`)

```bash
# Clone and enter the repo
git clone <repository-url>
cd security-detection-platform

# Virtual environment
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start PostgreSQL
sudo service postgresql start

# Create database and user
sudo -u postgres psql -c "CREATE USER sdp_user WITH PASSWORD 'sdp_password';"
sudo -u postgres psql -c "CREATE DATABASE sdp_db OWNER sdp_user;"
sudo -u postgres psql -c "GRANT ALL ON SCHEMA public TO sdp_user;"

# Config
cat > .env <<'EOF'
DATABASE_URL=postgresql://sdp_user:sdp_password@localhost/sdp_db
SECRET_KEY=replace-with-a-long-random-string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
EOF

# Seed test users, then run (tables are created on startup)
python seed.py
uvicorn app.main:app --reload
```

App runs at `http://127.0.0.1:8000`; `/` redirects to `/login`.

## 3. Test Users

`seed.py` is idempotent — safe to re-run.

| Username | Password | Role | Access |
|---|---|---|---|
| `admin` | `admin123` | admin | Everything, plus manage customers/signatures |
| `analyst` | `analyst123` | analyst | Claim/close detections |
| `readonly` | `readonly123` | readonly | View-only |

## 4. Demo Data

`seed.py` also creates customers, signatures, and a couple of open
detections so the queue isn't empty on first login. Each step is skipped if
that data already exists.

**Customers**

| Name | Importance |
|---|---|
| Acme Corp | 10 |
| GlobalBank | 8 |
| TechStartup | 4 |

**Signatures**

| Name | Priority | Fields |
|---|---|---|
| SSH Brute Force | 8 | `event_type=auth_failure`, `protocol=ssh` |
| Malware Detected | 10 | `event_type=malware`, `severity=high` |
| Port Scan | 5 | `event_type=recon`, `protocol=tcp` |

**Open Detections** (priority = customer importance × signature priority)

| Customer | Signature | Priority |
|---|---|---|
| GlobalBank | SSH Brute Force | 64 |
| Acme Corp | Malware Detected | 100 |

## 5. Tech Stack

| Choice | Why |
|---|---|
| **FastAPI** | Async, native Pydantic validation, `Depends`-based auth fits per-route role checks cleanly. |
| **Uvicorn** | ASGI server for FastAPI; `--reload` for local dev. |
| **PostgreSQL** | Row-level locking (`SELECT ... FOR UPDATE`) for the claim race, native JSON column, real FK integrity. |
| **SQLAlchemy 2.0** | Typed ORM models; direct access to `with_for_update()`. |
| **Pydantic v2** | Request/response validation at every route boundary. |
| **Jinja2** | Server-rendered pages — no separate frontend build for a CRUD console. |
| **python-jose** | JWT encode/decode for the auth cookie. |
| **bcrypt** | Password hashing. |
| **python-dotenv** | Loads `.env` config locally. |
| **python-multipart** | Parses the login form. |

## 6. Architecture Decisions

**FastAPI over Flask/Django.** Endpoints are small and independently
role-gated. `Depends` composes auth checks (`require_admin`,
`require_analyst`, `require_readonly`) without middleware or class-based
views, and Pydantic validation is native. Django's ORM/admin is more than
this needs; Flask would require extensions to match what FastAPI gives out
of the box.

**PostgreSQL over SQLite.** SQLite locks at the file level, not per-row —
under concurrent claims that serializes *all* writes, not just the
contended one. The claim-race fix depends on `SELECT ... FOR UPDATE`;
signature `fields` also wants a native JSON column and the schema relies on
real FK integrity.

**JWT in an HTTP-only cookie, not localStorage.** Pages are server-rendered
with form submits and redirects, not an SPA calling an API with a bearer
token. An HTTP-only cookie is sent automatically and unreadable by JS,
closing the main XSS token-theft vector `localStorage` has. Trade-off is
CSRF, mitigated with `SameSite=Lax`.

**Signature matching.** `_find_best_signature` matches when a signature's
fields are a subset of the incoming event
(`signature.fields.items() <= incoming.items()`), so signatures can be as
broad or narrow as needed. On multiple matches: highest `priority` wins,
ties go to the more specific match (more fields), remaining ties break on
lowest `id`.

**Priority = importance_level × signature.priority, not addition.**
Multiplication lets the two factors scale each other — a low-severity
signature on a top-tier customer can still outrank a high-severity
signature on a customer nobody cares about. Addition would apply a fixed
offset regardless of customer importance, compressing the range.

**Race condition — `SELECT ... FOR UPDATE`.** Two analysts claiming the
same detection simultaneously is a lost-update race. The claim endpoint
locks the row with `with_for_update()`; the second request blocks until
the first commits, then sees `status=active` and returns `409` instead of
double-assigning.

**Unmatched incidents are accepted, not rejected.** A signature miss is a
platform config gap, not a client error — `POST /incidents/ingest` returns
`200 {"matched": false}` and creates no `Detection`, rather than a `4xx`.
Leaves room for a future dead-letter table without changing the ingestion
contract.

**Polling over WebSockets for the active-detection overlay.** It answers
one low-frequency question, and the state only changes on actions the
current tab already triggered (claim/close refresh immediately
client-side). A push channel would add connection lifecycle and reconnect
complexity for a case that tolerates a few seconds of staleness.

## 7. AI Usage

This project was built with Claude Code, used interactively throughout
development to implement route handlers, database logic, and templates
from explicit specifications. Every decision — endpoints, roles, locking
strategy, priority formula, matching logic, UI behavior — was directed by
a human, with each change manually verified against a running server
before being accepted.

## 8. Known Limitations & Future Improvements

- **`importance_level` is validated only at the API layer** (Pydantic
  `ge=1, le=10`) — no DB `CHECK` constraint, so a direct write could store
  an out-of-range value.
- **Overlay polls every 15s instead of pushing** — fine at current scale;
  revisit if open-tab count grows or near-real-time push becomes a
  requirement.
- **Auth cookie isn't `secure=True`** — fine over local HTTP, must be set
  before deploying behind HTTPS.
- **No pagination** on `/detections/queue` or `/detections` — both load
  the full result set.
- **Test suite covers the core paths, not everything** — `tests/` (pytest)
  covers signature matching, priority calculation, role enforcement, and
  the claim conflict, and runs in CI on every push/PR to `main`.
  `test_ingest.py` is still a separate manual smoke script, and there's no
  coverage yet for customer/signature CRUD or the detections search/filter
  view.
- **`requirements.txt` has unused packages** (`alembic`, `passlib`) from
  initial scaffolding — schema uses `create_all`, hashing uses `bcrypt`
  directly.

## 9. Feature Checklist

**Auth & Access Control**
- [x] Login/logout, JWT in HTTP-only `SameSite=Lax` cookie — `auth_routes.py`
- [x] `get_current_user`, `require_admin`, `require_analyst`, `require_readonly` — `auth.py`

**Incident Ingestion**
- [x] `POST /incidents/ingest` — subset-match signature selection, priority = importance × signature priority, `200`/no-op on no match — `incidents.py`

**Detection Queue**
- [x] `GET /detections/queue` — open detections, priority desc, Claim button gated to analyst/admin
- [x] `POST /detections/queue/claim/{id}` — `SELECT FOR UPDATE`, `409` on race, else claims — `detections.py`

**Full Detections View**
- [x] `GET /detections` — search by customer/signature name, filter by status

**Active Detection Overlay**
- [x] `GET /detections/active`, polled every 15s from `base.html`, close action included

**Closing Detections**
- [x] `POST /detections/close/{id}` — analyst-only, ownership enforced, sets closed + resolution

**Customers / Signatures (Admin-managed)**
- [x] Full CRUD for both, admin-only writes, view-only for other roles — `customers.py`, `signatures.py`
- [x] `importance_level` validated 1–10; signature `fields` stored as a JSON dict
- [x] Templates hide add/edit/delete UI from non-admins

**Shared UI**
- [x] `base.html` — dark theme, nav, logout, persistent overlay across pages
