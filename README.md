# SentinelAI 🛡️

**SentinelAI** is an intelligent security gateway that detects, inspects, and prevents sensitive data leakage (PII, secrets, API keys) and prompt injections before prompts ever reach AI models.

Designed for high reliability and clean hackathon collaboration with a team of four.

---

## 🚀 Key Features

- **Sensitive Data Detection**: Scans prompts in real time for PII (emails, phone numbers, SSNs, credit cards) and secrets (API keys, private tokens, passwords).
- **Zero Raw Data Storage**: Adheres to strict privacy principles: raw sensitive user prompts are **never stored** in logs. Only risk metadata, incident counters, and sanitized previews are recorded.
- **Redaction & Blocking**: Flexible policies to either redact/mask sensitive entities (`[REDACTED_API_KEY]`) or block high-risk requests outright.
- **Prompt Injection Defense**: Intercepts jailbreaks and system-override instructions before forwarding to the model.
- **Document Permission Enforcement**: Validates user access levels against requested document contexts to prevent unauthorized internal data leakage.
- **Mock LLM by Default**: Easily testable end-to-end without requiring paid third-party API keys. Ready for external provider integration (OpenAI/Anthropic) when desired.

---

## 🏗️ Architecture Overview

```text
                  +----------------------------------------------+
                  |              Frontend (React + Vite)         |
                  |   • Prompt Playground  • Security Dashboard  |
                  |   • Policy Rules Config • Incident Logs      |
                  +----------------------------------------------+
                                         │  (HTTP / JSON)
                                         ▼
                  +----------------------------------------------+
                  |            FastAPI Security Gateway          |
                  |  1. Permission Check (User Role vs Doc Access)|
                  |  2. Prompt Injection Detection               |
                  |  3. PII & Secret Scanner (Detector Engine)   |
                  |  4. Policy Evaluator (Block / Mask / Allow)  |
                  |  5. Audit Logger (Sanitized Preview Only)    |
                  +----------------------------------------------+
                                   │            │
                     (If Blocked) ─┘            ▼ (If Allowed / Sanitized)
              Returns 403 / Alert         +------------------------+
                                          | Mock LLM / External AI |
                                          +------------------------+
```

---

## 📁 Project Structure

```text
sentinel-ai/
├── README.md
├── .gitignore
├── backend/                         # Python FastAPI Backend
│   ├── requirements.txt             # Backend dependencies
│   ├── .env.example                 # Environment variables template
│   └── app/
│       ├── main.py                  # FastAPI application entrypoint
│       ├── core/
│       │   └── config.py            # Gateway configurations & defaults
│       ├── models/
│       │   └── schemas.py           # Pydantic request/response & log models
│       ├── engine/
│       │   ├── detector.py          # PII & Secret detection routines
│       │   ├── injection.py         # Prompt injection heuristics
│       │   ├── anonymizer.py        # Masking & token replacement
│       │   ├── permissions.py       # Document access control enforcement
│       │   └── policy.py            # Rule engine (Block, Mask, Allow)
│       ├── services/
│       │   ├── mock_llm.py          # Zero-cost local mock LLM provider
│       │   └── storage.py           # Privacy-safe audit log storage
│       └── api/
│           ├── routes_gateway.py    # Main gateway intercept & scan endpoint
│           ├── routes_logs.py       # Privacy-safe audit logs endpoint
│           └── routes_rules.py      # Security policy configuration endpoint
│
└── frontend/                        # React Frontend (Vite)
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx                  # Main interface
        ├── services/api.js          # API client for backend communication
        └── components/
            ├── Playground.jsx       # Interactive sandbox to test prompts
            ├── AuditLogsTable.jsx   # Incident log viewer (sanitized)
            └── PolicySettings.jsx   # Rule configuration toggles
```

---

## 👥 4-Person Hackathon Team Division

To prevent Git merge conflicts during rapid development:
- **Member 1 (Frontend)**: Playground UI, logs dashboard, and policy toggles in `frontend/`.
- **Member 2 (API & Platform)**: FastAPI setup, routing, schemas, and privacy-preserving storage in `backend/app/api/` and `storage.py`.
- **Member 3 (Detection & Injection)**: PII/Secret regex patterns and prompt injection heuristics in `backend/app/engine/detector.py` and `injection.py`.
- **Member 4 (Policy, Permissions & LLM)**: Access control checks, masking logic, and LLM orchestration in `backend/app/engine/` and `mock_llm.py`.
