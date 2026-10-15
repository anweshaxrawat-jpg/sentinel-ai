# Deploy SentinelAI on Streamlit Community Cloud

## Main file path
Set **Main file path** to `streamlit_app.py`. This file is at the repository root in this ZIP.

## Upload
Extract this ZIP and upload its *contents* to the root of your GitHub repository. Do not upload the ZIP itself, and do not place these files inside `frontend/` or inside another `sentinel-ai-main/` folder. Your GitHub root should show `streamlit_app.py`, `requirements.txt`, `.streamlit/`, `backend/`, and `frontend/`.

## Configure the backend
The Streamlit UI calls the existing FastAPI backend. Deploy the backend separately, then open Streamlit app settings → **Secrets** and add:

```toml
API_BASE_URL = "https://YOUR-PUBLIC-FASTAPI-BACKEND-HOST"
```

Use the public base URL only (do not append `/api` and do not use `localhost`). The app accepts a URL ending in `/api`, too, but the base URL is preferred.

## Backend deployment
The backend code is in `backend/`. Its Python requirements are in `backend/requirements.txt`. Configure the backend service's working directory/import path according to its host; the FastAPI app is `app.main:app` when `backend` is the working directory and is on the Python path. Verify `https://YOUR-PUBLIC-FASTAPI-BACKEND-HOST/api/health` returns JSON with `status: healthy`.

## Important limitations
The backend currently uses a mock LLM and in-memory audit/policy storage. Logs and policy changes may reset when the backend restarts.
