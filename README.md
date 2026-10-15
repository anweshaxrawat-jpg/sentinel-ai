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

Member 1 — Backend & Security Engine

Owns the existing FastAPI backend, security detection, data masking, policy enforcement, permissions, audit logging, and backend testing.

Member 2 — Frontend & UI/UX

Builds the React + Vite + TypeScript frontend, including the cybersecurity dashboard, Attack Lab, Knowledge Vault, Policy Center, and integration with backend APIs.

Member 3 — Groq AI Integration

Integrates Groq-powered AI analysis, manages provider configuration securely, handles API errors, and preserves deterministic security controls and mock mode.

Member 4 — Investigation Engine & Attack Lab

Builds synthetic attack scenarios, incident investigation, evidence timelines, counterfactual replay, and security benchmarking with measurable results.
