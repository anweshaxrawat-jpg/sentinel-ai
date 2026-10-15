# AegisAI Frontend — Vercel deployment

React + TypeScript + Vite frontend for the AegisAI FastAPI security gateway. The frontend is configured for Vercel static hosting and uses the existing backend API.

## Deploy the frontend to Vercel

1. Push this project to a GitHub repository. Keep the `frontend/` directory in the repository.
2. In Vercel, choose **Add New → Project** and import that repository.
3. Set **Root Directory** to `frontend`.
4. Framework preset: **Vite**. Build command: `npm run build`. Output directory: `dist`. Install command: `npm install`. The included `vercel.json` configures these values and SPA routing.
5. In **Project Settings → Environment Variables**, add:
   - Name: `VITE_API_BASE_URL`
   - Value: the deployed FastAPI backend origin, for example `https://your-api-service.example.com` (use your actual URL; no trailing slash and no `/api`).
6. Redeploy after setting the variable. Vite environment variables are embedded at build time.

**Important:** Vercel hosts this frontend, not the Python API. The FastAPI backend must be deployed separately on a Python-compatible host and accessible publicly over HTTPS. A URL such as `http://127.0.0.1:8000` only works on your own computer and must not be used in Vercel production settings.

## Configure backend CORS

On the backend hosting provider, set the environment variable `ALLOWED_ORIGINS` to the exact Vercel origin, for example:

```text
ALLOWED_ORIGINS=https://your-project.vercel.app
```

For more than one origin, separate values with commas. Include the production domain and any preview domain you intentionally want to permit. Redeploy/restart the backend after changing this variable. Do not use `*` for production if you intend to use credentials or need a restricted origin policy.

## Local development

Requirements: Node.js 18+ (Node 20+ recommended) and Python 3.10+.

Start the API from the repository root:

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite development proxy forwards `/api` requests to `http://127.0.0.1:8000`, so no local `.env` file is needed.

## Build locally

```bash
npm run build
npm run preview
```

## API capabilities and limitations

Connected endpoints: `GET /api/health`, `POST /api/gateway/scan`, `GET /api/logs`, `GET /api/logs/metrics`, `GET /api/rules`, and `POST /api/rules`. The supplied backend uses a mock LLM by default and keeps logs/policies in memory, so they reset when the API process restarts. Persistent storage and alert/benchmark endpoints are not included in the supplied backend.

Do not put API keys or other secrets in `VITE_*` variables; frontend environment variables are public in the built JavaScript.


## Design refresh
The frontend uses a restrained charcoal enterprise security design with muted slate, emerald, and amber status colors. Existing API calls and backend-driven metrics are preserved; values not provided by the API (such as benchmark accuracy or measured inspection overhead) are not fabricated.
