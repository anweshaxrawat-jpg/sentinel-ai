# SentinelAI — Vercel Frontend

This folder is the **frontend-only** Vite + React + TypeScript project. Upload these files directly to the root of a GitHub repository, or use this folder as the Vercel project root. Do not set the Vercel Root Directory to `frontend` when these files are already at repository root.

## Vercel settings

- Framework preset: **Vite**
- Root Directory: `.` (repository root)
- Build command: `npm run build`
- Output directory: `dist`
- Install command: `npm install`

The `vercel.json` file already includes these build settings and an SPA fallback.

## Backend connection

The UI can build without a backend URL. To use live gateway scans, metrics, logs, and policy settings, deploy the FastAPI backend separately and add this environment variable in Vercel Project Settings → Environment Variables, for **Production** (and Preview if needed):

`VITE_API_BASE_URL=https://your-public-fastapi-backend.example.com`

Use the backend origin only: no trailing slash and **do not append `/api`**. Then redeploy. The backend must allow your Vercel domain in its CORS configuration.

## Local run

```bash
npm install
npm run dev
```

## Build locally

```bash
npm run build
```

If Vercel still fails, copy the first actual error line from **Deployments → Build Logs**; the deployment log distinguishes dependency, TypeScript, and configuration errors.
