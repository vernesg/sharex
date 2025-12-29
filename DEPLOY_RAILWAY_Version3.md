# Deploying to Railway

Railway supports multiple approaches: direct Docker, or creating two separate services (one for backend, one for frontend) using GitHub integration. The simplest approach for this monorepo is to create two services in Railway, each pointing at a different subfolder.

Option A — Create two Railway services (recommended)
1. On Railway, create a new project.
2. Add a service > Deploy from GitHub.
3. Connect your repo and set the Root Directory for each service:
   - Backend service
     - Root Directory: `/backend`
     - Install / Build: `npm install && npm run build`
     - Start: `npm start`
     - Set Environment Variables:
       - PORT = 4000
     - Add any secret tokens/cookies via Railway's Environment settings (do NOT commit them).
   - Frontend service
     - Root Directory: `/frontend`
     - Build: `npm install && npm run build`
     - Start: Use Railway's static deployment (serve the `dist`) or deploy via the provided Dockerfile:
       - If using Dockerfile, set it to use `/frontend/Dockerfile`
       - Or use the built static output and a simple Node server to serve `dist`
     - Set environment variable:
       - VITE_API_URL = https://<your-backend-service>.railway.app

Option B — Deploy with Docker
- Railway supports Docker-based services. When creating a service choose Docker and point to the `backend/Dockerfile` or `frontend/Dockerfile`.

railway.json template
- Some teams keep a `railway.json` as documentation or to seed Railway via their CLI. The included `railway.json` is a simple template — you'll still need to configure secrets via Railway UI.

Production notes
- As with Render: use DB for tokens, add authentication, add rate-limiting and retry/backoff to the job runner.
- Railway ephemeral instances: ensure you understand data persistence. File-based tokens.json may not survive across restarts or scaled instances. Use Postgres or key-value secrets.