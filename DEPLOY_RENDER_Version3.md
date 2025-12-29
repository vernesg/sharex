# Deploying to Render

This file explains how to deploy both backend and frontend to Render using `render.yaml` (included at repo root).

Important reminders
- Only deploy accounts/cookies you own and have permission to automate. Automated posting can violate Facebook's Terms of Service; use responsibly.
- Keep cookies/tokens secret — use Render's Environment settings to store them (do NOT commit them to the repo).

What this repo expects
- Backend service lives in `/backend`. It contains a Dockerfile and runs on port 4000.
- Frontend lives in `/frontend`. It contains a Dockerfile which builds the static site (served by Nginx).

Using render.yaml (recommended)
1. Commit `render.yaml` (included) to the repository root.
2. On Render, connect your GitHub repository.
3. Render will detect services from `render.yaml` and create two services:
   - fb-autoshare-backend (Docker)
   - fb-autoshare-frontend (Docker)

Environment variables (backend)
- PORT: 4000 (default present)
- Any sensitive tokens/cookies should be set via Render's Environment tab (not in repo).
  - Example names you can create:
    - DATA_DIR (optional)
  - NOTE: The backend stores tokens at `/app/data/tokens.json`. It will persist on the Render instance between deploys (but use DB for production).

Render-specific file (render.yaml)
- The included `render.yaml` instructs Render to build using the Dockerfile in each folder and to expose the backend service on port 4000.

Manual service creation (if you prefer)
- Create two services manually in Render:
  - Backend
    - Environment: Docker
    - Dockerfile Path: `/backend/Dockerfile`
    - Build Command: leave default (Docker does build)
    - Start Command: Docker CMD from Dockerfile
    - Env vars: add PORT=4000
  - Frontend
    - Dockerfile Path: `/frontend/Dockerfile`
    - Build and start handled by Dockerfile (served with Nginx)
4. After deployment open:
   - Backend URL: https://<your-backend>.onrender.com
   - Frontend URL: https://<your-frontend>.onrender.com

CORS / Client config
- Update the frontend environment variable VITE_API_URL to point to your backend URL. You can set it in the frontend service Environment settings or rebuild with VITE_API_URL pointing to the backend.

Production notes
- Replace file-based token storage with a database (Postgres + Prisma) for reliability and security.
- Add auth to protect cookie/token management endpoints.
- Add server-side rate-limits and backoff to avoid platform suspension.
