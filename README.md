# 🛡️ CyberGuardian: Consumer Cybersecurity Decision-Support & Threat Intelligence Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61DAFB?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind_CSS-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Gemini AI](https://img.shields.io/badge/AI-Google_Gemini-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev/)
[![SQLite](https://img.shields.io/badge/Persistence-SQLite%20%2F%20SQLAlchemy-003B57?style=flat&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Docker](https://img.shields.io/badge/Container-Docker_Compose-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Pytest-28_Passed-success?style=flat&logo=pytest&logoColor=white)]()

> **USP:** *Analyze. Explain. Protect. Learn.*

CyberGuardian is an AI-powered personal cybersecurity decision-support platform designed to help everyday users determine whether suspicious digital content is safe, risky, or malicious. 

Targeted initially at **college students and young adults in India**, the platform provides protection against modern social-engineering threats, including **fake internships, recruitment fraud, UPI/payment lures, KYC phishing, and QR-code scams (Quishing)**.

---

## 🎯 The Core Philosophy: "Evidence First, AI Explains"

Unlike systems that use an LLM as a black-box detector, CyberGuardian enforces strict architectural separation:

  USER INPUT (URL / QR / Message / Batch)
                            ↓
                     ANALYSIS LAYER
    (Lexical Forensics, Entropy, NLP Heuristics, Threat Feeds)
                            ↓
                    SECURITY EVIDENCE
                            ↓
                DETERMINISTIC RISK ENGINE
               (Transparent 0–100 Scoring)
                            ↓
                 GROUNDED AI EXPLAINER
               (Grounded in Evidence Only)
                            ↓
                 HUMAN-READABLE RESULT
                (Why? + Action + Education)

1. **Evidence First:** Security rules and heuristics extract factual technical and social engineering indicators.
2. **Deterministic Risk Assessment:** A transparent, rule-based scoring engine computes a risk score ($0 - 100$) and risk severity level.
3. **AI Explains:** Google Gemini translates the technical evidence into plain English without hallucinating or inventing threat indicators.
4. **Actionable Output:** Prescribes clear user guidance (*"Do not click"*, *"Verify via official portal"*).
5. **Education:** Explains the underlying social-engineering tactic (urgency, authority bias, scarcity) to build long-term user awareness.

---

## 📸 Key Features

| Modality | Features & Detection Capabilities |
| :--- | :--- |
| **URL Threat Scanner** | Shannon entropy analysis, Punycode/homograph detection, suspicious TLD detection (`.xyz`, `.top`, `.tk`), IP address hosting, SSL validity, and domain age analysis. |
| **QR Code (Quishing) Analyzer** | Image extraction via `pyzbar` and `Pillow`, payload sanitization, and automated routing into deep URL inspection. |
| **Social Engineering & Phishing NLP** | Rule-based detection of psychological manipulation lures: artificial urgency ("24 hours left"), authority impersonation ("Official KYC Notice"), financial bait ("Claim ₹10,000", UPI scams), and credential harvesting. |
| **Multi-Target Batch Triage** | High-throughput concurrent triage (up to 50 URLs or messages) using asynchronous worker semaphores, automatic risk sorting, and CSV export. |
| **Grounded AI Explainer** | Evidence-grounded breakdown generating: **Why is this risky?**, **What should you do?**, and **What can you learn?** |
| **Forensic PDF & CSV Reports** | Vector-rendered audit PDFs (via ReportLab) and structured CSV exports for auditing and documentation. |
| **Scan History & Analytics** | Privacy-conscious local persistence via SQLite/SQLAlchemy with real-time risk breakdown charts. |

---

## 📊 Deterministic Risk Engine Rubric

The deterministic engine evaluates evidence additively ($0 - 100$ scale). A score of 82 means *82/100 based on verified evidence indicators*, not an arbitrary probability:

| Risk Score Range | Classification | Prescribed Action |
| :---: | :---: | :--- |
| **0 – 29** | 🟢 **Low Risk** | *"No significant indicators detected. Remain cautious."* |
| **30 – 59** | 🟡 **Medium Risk** | *"Proceed carefully and verify the sender through official channels."* |
| **60 – 79** | 🟠 **High Risk** | *"Do not click or submit sensitive information/credentials."* |
| **80 – 100** | 🔴 **Critical Risk** | *"Do not interact. Block/report the sender immediately."* |

---

## ⚡ Quick Start

### 1. Environment Configuration
Create a `.env` file in the project root:
``env
GEMINI_API_KEY=your_gemini_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key_here
URLHAUS_API_KEY=optional_urlhaus_api_key
DATABASE_URL=sqlite:///./cyberguardian.db

#BACKEND SETUP

# Set up virtual environment
python -m venv venv
.\venv\Scripts\activate       # Windows
source venv/bin/activate       # Linux/macOS

# Install dependencies & run backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001 --app-dir backend

#Frontend Setup
cd frontend
npm install
npm run dev

Open http://localhost:5173 in your browser.

🛡️ Defensive Engineering & Graceful Degradation
CyberGuardian treats all user inputs as untrusted data:

Graceful Degradation: If an external threat intelligence API (like URLhaus or Safe Browsing) fails or returns 401/429/500, the core heuristic engine continues evaluating without crashing.
LLM Prompt Injection Defense: User inputs are treated strictly as untrusted data strings within prompt boundaries, preventing manipulation of the AI explainer.
SSRF Mitigation: Isolated URL analysis sanitizes raw network targets and avoids arbitrary internal loopback fetches.
Privacy-First Handling: No mandatory account creation; minimum required telemetry stored locally.

🧪 Testing Suite
Run the unit and integration test suite:

Bash
pytest
Status: 28 tests passing across URL analysis, QR parsing, NLP rules, risk engine, threat intel, and PDF generation.

⚖️ License
Licensed under the MIT License.
