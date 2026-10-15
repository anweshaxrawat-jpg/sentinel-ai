# Deploy SentinelAI on Streamlit Community Cloud

This repository now includes a Streamlit frontend at `streamlit_app.py`. The existing FastAPI backend and its detection, policy, and audit code are unchanged. Streamlit hosts only the UI; FastAPI must run separately at a publicly reachable HTTPS URL.

## Deploy

1. Push this project to a GitHub repository you can access.
2. Open <https://share.streamlit.io/> and choose **Create app**.
3. Select the repository and branch.
4. Set **Main file path** to `streamlit_app.py`.
5. Deploy the app.
6. In the deployed app's **Settings → Secrets**, add:

   ```toml
   API_BASE_URL = "https://your-public-fastapi-host.example.com"
   ```

   Use the backend origin only. Do not append `/api`; the app adds that prefix automatically. Do not use `localhost` for the deployed backend URL.

7. Ensure the backend is deployed separately and that its `/api/health` endpoint is reachable. The current API is server-to-server from Streamlit, so browser CORS is not needed for these Streamlit-to-FastAPI requests.

## Run locally

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Set `API_BASE_URL` to the backend origin in your shell, then run:

```bash
streamlit run streamlit_app.py
```

Alternatively, create `.streamlit/secrets.toml` locally (do not commit it):

```toml
API_BASE_URL = "http://127.0.0.1:8000"
```

## What is included

- Security overview with backend-reported request counts and recent audit records.
- Gateway playground calling `POST /api/gateway/scan` and showing the real response.
- Audit trail using `GET /api/logs`.
- Policy center using `GET /api/rules` and `POST /api/rules`.
- System health using `GET /api/health`.

## Important behavior and limitations

- The backend's current LLM provider is a mock by default; this UI does not replace it with a hosted LLM.
- Document access checks use the document metadata submitted with the request. This is not a complete RAG document store.
- Backend audit logs and policy configuration are in-memory and may reset when the backend process restarts.
- Dashboard counts come from the API; no synthetic accuracy, threat, or latency numbers are fabricated.
- The displayed API round-trip time includes network time and is not presented as gateway-only overhead.
- Use synthetic prompts for demonstrations; never enter actual credentials or personal data.
