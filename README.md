# CyberGuardian

**Scam and phishing investigator.** Paste a link, a message, a QR code image or a list of links. CyberGuardian collects evidence, scores the risk, and explains the verdict in plain language.

> *Evidence first, AI explains.* Every verdict comes from deterministic checks and threat feeds. The AI only writes the explanation from that evidence. It never decides the score.

**Live demo:** https://cyberguardian.nikitabalyan311.workers.dev
The API runs on a free hosting plan and sleeps after 15 minutes of inactivity, so the first request after a quiet period can take about a minute.

## What it does

- **URL scan:** follows the redirect chain, checks TLS, domain age (WHOIS), brand lookalikes and threat feeds, and runs a hostname classifier.
- **Message scan:** finds urgency and financial-lure language and suspicious senders, then scans every link in the message.
- **QR scan:** decodes an uploaded image and scans the URL inside it.
- **Batch scan:** up to 50 URLs or messages at once. Targets that cannot be scanned are marked *Not verified*, never "safe".
- **History:** your own scans, with search, filters and a "delete my history" button.
- **Reports:** per-scan export to PDF, JSON or Markdown, plus CSV export for batches.
- **Signal table and evidence drawer:** every finding shows its source (rule, ML, threat feed) so the verdict can be audited.

## How it works

```
input (URL / message / QR / batch)
   -> evidence collection
        redirect chain (SSRF-safe) | TLS validity | WHOIS domain age
        brand lookalike check      | URLhaus + Google Safe Browsing
        12 lexical features -> hostname-only XGBoost score
   -> risk engine
        composite = 0.6 x heuristics + 0.2 x ML + 0.2 x feed hits
        a threat-feed hit pins the score to at least 95 (CRITICAL)
   -> Gemini writes the explanation from the structured evidence
   -> result + audit log (per anonymous visitor)
```

**Heuristic points:** threat-feed hit +60 (capped), domain younger than 14 days +25 (up to 30 days +15), brand impersonation +25, missing or invalid TLS +15, suspicious TLD +10, raw IP host +20, more than 2 redirects +15. Messages add urgency +20, financial lure +25 and suspicious sender +15 to the score of the worst embedded link.

**Levels:** LOW below 30, MEDIUM 30-59, HIGH 60-79, CRITICAL 80 and above.

## The ML model, and what it can and cannot do

A hostname-only XGBoost classifier over 12 lexical features supplies **20% of the score**. It looks only at the shape of the hostname (length, dots, digits, TLD, entropy, and so on), so it is a weak, supporting signal.

| Evaluation | Result |
|---|---|
| Domain-grouped test set (same site never in train and test) | ROC-AUC about 0.78, precision 0.84, recall 0.57 at the 0.5 cutoff |
| False alarms on legitimate hosts at the 0.5 cutoff | about 10% |
| Independent OpenPhish sample (167 distinct domains, not in training) | about 69% detected |

**Lesson learned.** An earlier version reached 99.6% accuracy. The report showed why: benign training URLs were bare homepages and phishing URLs had paths and different schemes, so the model had learned "has a path means phishing". The model now sees only the hostname, benign data includes real subdomains (Chrome UX Report top sites), and the headline numbers are the grouped-split and second-source results above.

Training data: [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967) (UCI, CC BY 4.0), [CrUX top lists](https://github.com/zakird/crux-top-lists) for benign hosts, and the OpenPhish community feed for the independent test.

## Security design

- **SSRF-safe fetching:** only `http` and `https`, a port allowlist, DNS resolution checked against private, loopback and link-local ranges, and **every redirect hop re-validated**. Response bodies are never downloaded. DNS rebinding remains a residual risk, so production should also filter egress at the network level.
- **Abuse limits:** per-IP rate limits and a global daily scan cap protect third-party API quotas. Input sizes are capped.
- **Privacy:** history is scoped to a random per-browser ID (no accounts), saved scans expire after 30 days by default, and users can delete their own history. Pasted messages are stored in full for that period.
- **Hardening:** an explicit CORS allowlist, API docs hidden in production, no internal error details in responses, row-level security enabled on the database table, secrets only in environment variables, CSV formula-injection protection on exports, and unsafe link schemes stripped from rendered AI text.
- **Fail-safe scoring:** a scan that times out or fails is reported as *Not verified*, not as low risk.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan/url` | scan one URL |
| POST | `/api/v1/scan/message` | scan message text and its links |
| POST | `/api/v1/scan/qr` | scan a QR code image (multipart upload) |
| POST | `/api/v1/scan/batch` | scan up to 50 URLs or messages |
| GET / DELETE | `/api/v1/history` | list or delete the caller's scans (`X-Visitor-Id` header) |
| POST | `/api/v1/export/pdf` | render a scan as a PDF report |
| GET | `/api/v1/health` | liveness check |

Interactive docs are available at `/docs` when `APP_ENV` is not `production`.

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic, httpx, python-whois, tldextract, pyzbar and OpenCV (QR decoding), ReportLab (PDF)
- **ML:** XGBoost, scikit-learn, pandas
- **AI:** Google Gemini (explanations only)
- **Data:** PostgreSQL on Supabase in production, SQLite locally
- **Threat intelligence:** URLhaus and Google Safe Browsing
- **Frontend:** React 18, Vite, Tailwind CSS, light and dark themes
- **Hosting:** Cloudflare (frontend), Render (backend, Docker), Supabase (database)
- **Tests:** pytest, 59 automated tests

## Run it locally

```powershell
git clone https://github.com/nikita-balyan/cyberguardian.git
cd cyberguardian
python -m venv venv
.\venv\Scripts\Activate.ps1          # macOS/Linux: source venv/bin/activate
pip install -r requirements-dev.txt
copy .env.example .env               # then fill in your own keys
```

In `.env`, either leave `DATABASE_URL` empty to use a local SQLite file, or set it to your PostgreSQL URL.

Backend:
```powershell
uvicorn app.main:app --app-dir backend --reload --reload-dir backend --port 8000
```

Frontend (second terminal):
```powershell
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. The frontend calls `http://127.0.0.1:8000/api/v1` by default. Set `VITE_API_URL` to change it.

Tests: `pytest`

## Configuration

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL URL (empty means local SQLite) |
| `GEMINI_API_KEY` | explanations |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing lookups |
| `APP_ENV` | `production` hides the API docs |
| `CORS_ORIGINS` | comma-separated frontend origins |
| `CLIENT_IP_HEADER` | header carrying the real visitor IP behind a trusted proxy (for example `cf-connecting-ip` on Render) |
| `TRUST_PROXY_HEADERS` | use the last `X-Forwarded-For` entry (only behind a single trusted proxy) |
| `RATE_LIMIT_SCANS_PER_MIN`, `RATE_LIMIT_BATCHES_PER_HOUR`, `RATE_LIMIT_READS_PER_MIN` | per-IP limits (0 disables) |
| `GLOBAL_SCANS_PER_DAY` | daily cap across all visitors |
| `HISTORY_RETENTION_DAYS` | auto-delete age for saved scans (0 keeps everything) |

## Retraining the model

```powershell
# data: PhiUSIIL CSV from UCI -> data/ ; OpenPhish feed and CrUX list as below
Invoke-WebRequest https://openphish.com/feed.txt -OutFile data\openphish.txt
Invoke-WebRequest https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz -OutFile data\crux.csv.gz

python scripts/split_dataset.py
python scripts/prepare_crux.py
python -m backend.app.ml.train_model --phishing data\phishing_urls.txt --benign data\benign_urls.txt data\crux_benign.txt --holdout-phishing data\openphish.txt --host-only
python -m scripts.check_model
```
Commit the `.pkl` and its `.meta.json` together. The server reads the metadata to apply the same hostname reduction the model was trained with.

## Deployment

- **Backend:** Docker image built from `backend/Dockerfile`, deployed as a Render web service with the environment variables above.
- **Frontend:** `frontend/` built with `npm run build` and served as static assets by Cloudflare (`frontend/wrangler.jsonc`), with `VITE_API_URL` set as a build variable.
- **Database:** Supabase PostgreSQL. Run once: add the `owner_id` column and enable row-level security (see the SQL in the project notes).

## Limitations and responsible use

- **The protection offered by Google Safe Browsing is not perfect.** No single signal here is either. Expect false positives and false negatives, and do not treat a LOW result as a guarantee of safety.
- The ML score is a weak supporting signal, as described above.
- Google's Safe Browsing API is for **non-commercial use only**. A commercial deployment would need the Web Risk API or a different feed.
- Domain age depends on WHOIS data, which some registries do not provide. Missing data is treated as no signal.
- Free hosting means cold starts and limited memory.
- Scanning contacts the submitted site (response headers only). Submitted URLs and the derived evidence are sent to Google Safe Browsing, URLhaus and the Gemini API.
- This is a learning and portfolio project, not a replacement for endpoint or email security products.

## Credits

PhiUSIIL Phishing URL Dataset (UCI Machine Learning Repository, CC BY 4.0; see the dataset page for the citation), Chrome UX Report top lists, OpenPhish community feed, URLhaus (abuse.ch), Google Safe Browsing.
