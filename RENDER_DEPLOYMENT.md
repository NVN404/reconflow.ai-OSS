# Deploying ReconFlow AI to Render.com

This guide provides step-by-step instructions to deploy ReconFlow AI (both FastAPI Backend and Next.js Frontend) to [Render.com](https://render.com).

---

## Architecture Overview

ReconFlow AI consists of two services:
1. **`reconflow-api` (Backend)**: Python FastAPI server executing open-source multi-engine sweeps and Gemini Flash triage.
2. **`reconflow-frontend` (Frontend)**: Next.js 14 web application rendering the interactive Attack Surface Graph.

---

## Method 1: 1-Click Blueprint Deploy (Recommended)

1. Log into your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Blueprint**.
3. Select your repository: `NVN404/reconflow.ai-OSS`.
4. Render will detect `render.yaml` and configure both services automatically!
5. Fill in the required environment variables:
   - For `reconflow-api`:
     - `ENABLE_PROXY_ROTATION`: `"true"` (or `"false"`)
     - `GEMINI_API_KEY`: Your Gemini API key (optional, from https://aistudio.google.com/)
   - For `reconflow-frontend`:
     - `NEXT_PUBLIC_API_URL`: The deployed URL of your backend (e.g., `https://reconflow-api.onrender.com`)
6. Click **Apply**.

---

## Method 2: Manual Web Service Setup (Step-by-Step)

If you prefer setting up the services manually via the Render UI:

### Step 1: Deploy Backend Web Service (`reconflow-api`)

1. In Render Dashboard, click **New +** → **Web Service**.
2. Connect repository: `https://github.com/NVN404/reconflow.ai-OSS`.
3. Configure the settings:
   - **Name**: `reconflow-api`
   - **Region**: Oregon or Frankfurt
   - **Branch**: `main`
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Free
4. Under **Environment Variables**, add:
   | Key | Value | Description |
   | :--- | :--- | :--- |
   | `PYTHON_VERSION` | `3.11.9` | Recommended Python version |
   | `ENABLE_PROXY_ROTATION` | `true` | Built-in self-healing proxy rotation pool |
   | `GEMINI_API_KEY` | *(Your key, optional)* | Google Gemini Flash Key for AI triage |

5. Click **Create Web Service**.
6. Note the deployed backend URL once live (e.g., `https://reconflow-api.onrender.com`).

---

### Step 2: Deploy Frontend Web Service (`reconflow-frontend`)

1. In Render Dashboard, click **New +** → **Web Service**.
2. Connect the same repository: `NVN404/reconflow.ai-OSS`.
3. Configure the settings:
   - **Name**: `reconflow-frontend`
   - **Branch**: `main`
   - **Root Directory**: `frontend`
   - **Runtime**: `Node`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm run start`
   - **Instance Type**: Free
4. Under **Environment Variables**, add:
   | Key | Value | Description |
   | :--- | :--- | :--- |
   | `NODE_VERSION` | `20.16.0` | Node.js LTS version |
   | `NEXT_PUBLIC_API_URL` | `https://reconflow-api.onrender.com` | Public URL of Backend from Step 1 |
5. Click **Create Web Service**.

---

## Verifying Deployment

1. **Backend Health Check**:
   Visit `https://reconflow-api.onrender.com/health` (should return JSON `{ "status": "ok", ... }`).
2. **Frontend App**:
   Visit `https://reconflow-frontend.onrender.com`.
3. **Run a Test Audit**:
   - Audit `vulnweb.com` directly without authentication friction.
   - Inspect the interactive React Flow attack surface topology.
   - Export the 1-Click CISO Executive Markdown dossier.
