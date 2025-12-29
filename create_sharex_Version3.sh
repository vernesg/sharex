#!/usr/bin/env bash
set -euo pipefail

# create_sharex.sh
# Generates the FB AutoSharer project files and creates sharex.zip
#
# Usage:
#   chmod +x create_sharex.sh
#   ./create_sharex.sh
#
# After running this script you'll have a sharex.zip archive containing the project.
# The script does NOT run npm install. Run installs inside backend/ and frontend/ as needed.

ROOT_DIR="$(pwd)/sharex_project"
ZIP_NAME="sharex.zip"

echo "Creating project at: $ROOT_DIR"
rm -rf "$ROOT_DIR"
mkdir -p "$ROOT_DIR"

cd "$ROOT_DIR"

echo "Creating directories..."
mkdir -p backend/src/backend_ignore backend/data backend/src/routes backend/src/utils
mkdir -p frontend/src/pages frontend/src/styles frontend/src/components

# Helper to write files
write_file() {
  local path="$1"; shift
  local content="$1"
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<'EOF'
'"$content"'
EOF
}

# Because above helper with heredoc and embedded variables is cumbersome in this context,
# we will write files using cat <<'HEREDOC' ... HEREDOC blocks directly.

echo "Writing files..."

# README.md
cat > README.md <<'EOF'
# FB AutoSharer — Node + React (TypeScript)

Warning: This project automates Facebook actions using cookies and access tokens. Only use accounts you own and have permission to automate. Follow Facebook/Meta Terms and local law.

What this repo contains
- backend/ — Express + TypeScript backend (JWT auth, admin panel, share job runner)
- frontend/ — React + Vite + TypeScript + Tailwind frontend (UI, admin panel)
- docker-compose.yml, Dockerfiles — run locally or deploy to Render/Railway

Quick local dev (recommended)
1. Backend
   - cd backend
   - npm install
   - cp .env.example .env
   - edit .env with your values (JWT_SECRET, etc.)
   - npm run dev

2. Frontend
   - cd frontend
   - npm install
   - cp .env.example .env
   - set VITE_API_URL if backend runs elsewhere
   - npm run dev

3. Open the frontend at http://localhost:5173

Default admin account
- username: admin
- password: vina
Changeable in Admin Panel (only accessible when logged in as admin).

Data storage
- backend/data/ — file-based storage by default. For production use Postgres + Prisma.

Production / Deployment
- Use secure DB and encrypted secret storage for tokens and user passwords.
- Use Render/Railway deployment configs (render.yaml, railway.json) and set env vars in the platform.

Security notes
- Do NOT commit real FB cookies/tokens or secrets.
- For production replace file-based storage with a DB and encrypt tokens at rest.
EOF

# .gitignore
cat > .gitignore <<'EOF'
node_modules
dist
.env
backend/node_modules
frontend/node_modules
backend/data/*.json
.DS_Store
EOF

# docker-compose.yml
cat > docker-compose.yml <<'EOF'
version: "3.8"
services:
  backend:
    build: ./backend
    ports:
      - "4000:4000"
    environment:
      - PORT=4000
    volumes:
      - ./backend/data:/app/data
  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    environment:
      - VITE_API_URL=http://localhost:4000
EOF

####################################
# Backend files
####################################

cat > backend/package.json <<'EOF'
{
  "name": "fb-autoshare-backend",
  "version": "1.0.0",
  "private": true,
  "main": "dist/index.js",
  "scripts": {
    "dev": "ts-node-dev --respawn --transpile-only src/index.ts",
    "build": "tsc -p .",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "axios": "^1.5.0",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "p-limit": "^4.0.0",
    "socket.io": "^4.7.2",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "@types/express": "^4.17.17",
    "@types/jsonwebtoken": "^9.0.2",
    "@types/node": "^20.5.6",
    "ts-node-dev": "^2.0.0",
    "typescript": "^5.4.2"
  }
}
EOF

cat > backend/tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "CommonJS",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
EOF

cat > backend/.env.example <<'EOF'
# Copy to .env and fill with your own values
PORT=4000
JWT_SECRET=replace_with_a_strong_secret
TOKEN_FETCH_TIMEOUT_MS=10000
# (Optional) ENCRYPTION_KEY=base64_or_hex_key_for_encrypting_tokens
EOF

cat > backend/Dockerfile <<'EOF'
FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --production
COPY . .

RUN npm run build

EXPOSE 4000
CMD ["node", "dist/index.js"]
EOF

cat > backend/src/index.ts <<'EOF'
import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import authRouter from "./routes/auth";
import shareRouter from "./routes/share";
import adminRouter from "./routes/admin";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Socket: join rooms
io.on("connection", (socket) => {
  socket.on("join", (roomId: string) => {
    socket.join(roomId);
  });
});

app.locals.io = io;

app.use(cors());
app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/share", shareRouter);
app.use("/api/admin", adminRouter);

app.get("/api/health", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
server.listen(PORT, () => {
  console.log(`Backend listening on ${PORT}`);
});
EOF

cat > backend/src/storage.ts <<'EOF'
import fs from "fs/promises";
import path from "path";

const DATA_DIR = path.join(__dirname, "..", "data");

export type User = {
  id: string;
  username: string;
  passwordHash: string;
  isAdmin?: boolean;
  isPremium?: boolean;
  trialRemaining?: number;
};

export type TokenEntry = {
  token: string;
  cookie: string;
  addedAt: string;
};

export type CodeEntry = {
  code: string;
  createdAt: string;
  createdBy: string;
  redeemedBy?: string;
  redeemedAt?: string;
};

async function ensureDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function readJson<T>(filename: string, defaultValue: T): Promise<T> {
  try {
    await ensureDir();
    const raw = await fs.readFile(path.join(DATA_DIR, filename), "utf-8");
    return JSON.parse(raw) as T;
  } catch {
    return defaultValue;
  }
}

async function writeJson<T>(filename: string, data: T): Promise<void> {
  await ensureDir();
  await fs.writeFile(path.join(DATA_DIR, filename), JSON.stringify(data, null, 2), "utf-8");
}

export async function readUsers(): Promise<User[]> {
  const users = await readJson<User[]>("users.json", []);
  return users;
}

export async function writeUsers(users: User[]) {
  await writeJson("users.json", users);
}

export async function readTokens(): Promise<TokenEntry[]> {
  return await readJson<TokenEntry[]>("tokens.json", []);
}
export async function writeTokens(tokens: TokenEntry[]) {
  await writeJson<TokenEntry[]>("tokens.json", tokens);
}

export async function readCodes(): Promise<CodeEntry[]> {
  return await readJson<CodeEntry[]>("codes.json", []);
}
export async function writeCodes(codes: CodeEntry[]) {
  await writeJson<CodeEntry[]>("codes.json", codes);
}
EOF

cat > backend/src/utils/facebook.ts <<'EOF'
import axios from "axios";
import pLimit from "p-limit";
import { TokenEntry } from "../storage";
import { Server } from "socket.io";

const UA_LIST = [
  "Mozilla/5.0 (Linux; Android 10; Wildfire E Lite Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/105.0.5195.136 Mobile Safari/537.36[FBAN/EMA;FBLC/en_US;FBAV/298.0.0.10.115;]",
  "Mozilla/5.0 (Linux; Android 11; KINGKONG 5 Pro Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/320.0.0.12.108;]",
  "Mozilla/5.0 (Linux; Android 11; G91 Pro Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/106.0.5249.126 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/325.0.1.4.108;]"
];

export function parseCookieString(raw: string): string {
  return raw.trim();
}

export async function extractTokenFromFacebook(cookieHeader: string): Promise<string | null> {
  const ua = UA_LIST[Math.floor(Math.random() * UA_LIST.length)];
  try {
    const timeout = Number(process.env.TOKEN_FETCH_TIMEOUT_MS ?? 10000);
    const res = await axios.get("https://business.facebook.com/business_locations", {
      headers: {
        "User-Agent": ua,
        "Referer": "https://www.facebook.com/",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": cookieHeader
      },
      timeout
    });
    const text = String(res.data);
    const m = text.match(/(EAAG\w+)/);
    if (m) return m[1];
    return null;
  } catch (err: any) {
    throw new Error("Failed to fetch Facebook business page: " + String(err.message ?? err));
  }
}

async function shareOnce(token: string, cookieHeader: string, link: string): Promise<{ ok: boolean; body: any }> {
  const ua = UA_LIST[Math.floor(Math.random() * UA_LIST.length)];
  try {
    const url = `https://graph.facebook.com/v13.0/me/feed?link=${encodeURIComponent(link)}&published=0&access_token=${encodeURIComponent(token)}`;
    const res = await axios.post(url, null, {
      headers: {
        "User-Agent": ua,
        "Cookie": cookieHeader
      },
      timeout: 10000
    });
    return { ok: true, body: res.data };
  } catch (err: any) {
    if (err.response && err.response.data) return { ok: false, body: err.response.data };
    return { ok: false, body: String(err) };
  }
}

export async function startShareJob(params: {
  jobId: string;
  link: string;
  limit: number;
  chunkSize: number;
  cooldown: number;
  concurrency: number;
  tokens: TokenEntry[];
  io: Server;
  bypassCooldown?: boolean;
}) {
  const { jobId, link, limit, chunkSize, cooldown, concurrency, tokens, io, bypassCooldown = false } = params;
  const room = io.to(jobId);

  room.emit("log", { level: "info", message: `Job ${jobId} started: ${limit} shares` });

  const limitFn = pLimit(concurrency);
  let count = 0;
  let shareIndex = 1;
  const startTime = Date.now();

  while (shareIndex <= limit) {
    const tasks: Promise<void>[] = [];
    const thisChunk = Math.min(chunkSize, limit - shareIndex + 1);

    for (let i = 0; i < thisChunk; i++) {
      const chosen = tokens[Math.floor(Math.random() * tokens.length)];
      const n = shareIndex;
      const task = limitFn(async () => {
        const res = await shareOnce(chosen.token, chosen.cookie, link);
        const elapsed = new Date(Date.now() - startTime).toISOString().slice(11, 19);
        if (res.ok && res.body && res.body.id) {
          room.emit("log", { level: "success", message: `#${n} shared successfully (${elapsed})` });
        } else {
          room.emit("log", { level: "error", message: `#${n} failed: ${JSON.stringify(res.body)}` });
        }
      });
      tasks.push(task);
      shareIndex++;
      count++;
    }

    await Promise.all(tasks);

    if (!bypassCooldown && shareIndex <= limit) {
      room.emit("log", { level: "info", message: `Cooldown ${cooldown}s after ${count} shares...` });
      await new Promise((r) => setTimeout(r, cooldown * 1000));
    } else if (bypassCooldown && shareIndex <= limit) {
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  room.emit("log", { level: "info", message: `Job ${jobId} finished. Total attempts: ${count}` });
  room.emit("done", { jobId, total: count });
}
EOF

cat > backend/src/routes/auth.ts <<'EOF'
import express from "express";
import { parseCookieString, extractTokenFromFacebook } from "../utils/facebook";
import { readTokens, writeTokens, readUsers, writeUsers, User, readCodes, writeCodes } from "../storage";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET ?? "change_this_secret_for_prod";

function sign(user: { id: string; username: string; isAdmin?: boolean }) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
}

async function ensureAdminSeed() {
  let users = await readUsers();
  if (users.length === 0) {
    const pwHash = bcrypt.hashSync("vina", 10);
    const admin: User = {
      id: uuidv4(),
      username: "admin",
      passwordHash: pwHash,
      isAdmin: true,
      isPremium: true,
      trialRemaining: 0
    };
    users = [admin];
    await writeUsers(users);
  }
}

router.post("/register", async (req, res) => {
  await ensureAdminSeed();
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const users = await readUsers();
  if (users.find((u) => u.username === username)) return res.status(400).json({ error: "username exists" });
  const hash = await bcrypt.hash(password, 10);
  const newUser: User = { id: uuidv4(), username, passwordHash: hash, isAdmin: false, isPremium: false, trialRemaining: 3 };
  users.push(newUser);
  await writeUsers(users);
  const token = sign({ id: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin });
  res.json({ token, user: { id: newUser.id, username: newUser.username, isPremium: newUser.isPremium, trialRemaining: newUser.trialRemaining } });
});

router.post("/login", async (req, res) => {
  await ensureAdminSeed();
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const users = await readUsers();
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: "invalid credentials" });
  const token = sign({ id: user.id, username: user.username, isAdmin: user.isAdmin });
  res.json({ token, user: { id: user.id, username: user.username, isPremium: user.isPremium, trialRemaining: user.trialRemaining, isAdmin: user.isAdmin } });
});

router.get("/me", async (req, res) => {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  try {
    const payload: any = jwt.verify(auth, JWT_SECRET);
    const users = await readUsers();
    const user = users.find((u) => u.id === payload.id);
    if (!user) return res.status(401).json({ error: "user not found" });
    res.json({ user: { id: user.id, username: user.username, isPremium: user.isPremium, trialRemaining: user.trialRemaining, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(401).json({ error: "invalid token" });
  }
});

router.post("/cookies", async (req, res) => {
  const cookies: string[] = req.body.cookies;
  if (!Array.isArray(cookies) || cookies.length === 0) return res.status(400).json({ error: "cookies must be a non-empty array" });
  const tokens = await readTokens();
  const results: any[] = [];
  for (const raw of cookies) {
    try {
      const cookieHeader = parseCookieString(raw);
      const token = await extractTokenFromFacebook(cookieHeader);
      if (!token) {
        results.push({ cookie: cookieHeader, ok: false, error: "token not found" });
        continue;
      }
      tokens.push({ token, cookie: cookieHeader, addedAt: new Date().toISOString() });
      results.push({ cookie: cookieHeader, token, ok: true });
    } catch (err: any) {
      results.push({ cookie: raw, ok: false, error: String(err.message ?? err) });
    }
  }
  await writeTokens(tokens);
  res.json({ results, total: tokens.length });
});

router.get("/tokens", async (_req, res) => {
  const tokens = await readTokens();
  res.json({ tokens });
});

router.post("/redeem", async (req, res) => {
  const { code, auth } = req.body;
  if (!code) return res.status(400).json({ error: "code required" });
  if (!auth) return res.status(401).json({ error: "auth token required" });
  try {
    const payload: any = jwt.verify(auth, JWT_SECRET);
    const users = await readUsers();
    const userIdx = users.findIndex((u) => u.id === payload.id);
    if (userIdx === -1) return res.status(401).json({ error: "user not found" });
    const codes = await readCodes();
    const codeEntry = codes.find((c) => c.code === code && !c.redeemedBy);
    if (!codeEntry) return res.status(400).json({ error: "invalid or already redeemed code" });
    users[userIdx].isPremium = true;
    users[userIdx].trialRemaining = users[userIdx].trialRemaining ?? 0;
    codeEntry.redeemedBy = users[userIdx].username;
    codeEntry.redeemedAt = new Date().toISOString();
    await writeUsers(users);
    await writeCodes(codes);
    res.json({ ok: true, user: { username: users[userIdx].username, isPremium: users[userIdx].isPremium } });
  } catch (err: any) {
    res.status(401).json({ error: "invalid token" });
  }
});

export default router;
EOF

cat > backend/src/routes/admin.ts <<'EOF'
import express from "express";
import { readCodes, writeCodes, readUsers, writeUsers } from "../storage";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET ?? "change_this_secret_for_prod";

async function requireAdmin(req: any, res: any, next: any) {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  try {
    const payload: any = jwt.verify(auth, JWT_SECRET);
    const users = await readUsers();
    const user = users.find((u) => u.id === payload.id);
    if (!user || !user.isAdmin) return res.status(403).json({ error: "admin only" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

router.get("/codes", requireAdmin, async (req: any, res) => {
  const codes = await readCodes();
  res.json({ codes });
});

router.post("/codes", requireAdmin, async (req: any, res) => {
  const { count = 1 } = req.body;
  const codes = await readCodes();
  for (let i = 0; i < count; i++) {
    const code = uuidv4().replace(/-/g, "").slice(0, 10).toUpperCase();
    codes.push({ code, createdAt: new Date().toISOString(), createdBy: req.user.username });
  }
  await writeCodes(codes);
  res.json({ ok: true, created: count, codes: codes.slice(-count) });
});

router.post("/codes/revoke", requireAdmin, async (req: any, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code required" });
  const codes = await readCodes();
  const idx = codes.findIndex((c) => c.code === code && !c.redeemedBy);
  if (idx === -1) return res.status(404).json({ error: "code not found or already redeemed" });
  codes.splice(idx, 1);
  await writeCodes(codes);
  res.json({ ok: true });
});

router.post("/change-admin", requireAdmin, async (req: any, res) => {
  const { newUsername, newPassword } = req.body;
  if (!newUsername && !newPassword) return res.status(400).json({ error: "newUsername or newPassword required" });
  const users = await readUsers();
  const adminIdx = users.findIndex((u) => u.isAdmin);
  if (adminIdx === -1) return res.status(500).json({ error: "admin not found" });
  if (newUsername) users[adminIdx].username = newUsername;
  if (newPassword) users[adminIdx].passwordHash = await bcrypt.hash(newPassword, 10);
  await writeUsers(users);
  res.json({ ok: true });
});

router.get("/users", requireAdmin, async (req: any, res) => {
  const users = await readUsers();
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, isAdmin: u.isAdmin, isPremium: u.isPremium, trialRemaining: u.trialRemaining })) });
});

export default router;
EOF

cat > backend/src/routes/share.ts <<'EOF'
import express from "express";
import { readTokens, readUsers, writeUsers } from "../storage";
import { startShareJob } from "../utils/facebook";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET ?? "change_this_secret_for_prod";

router.post("/start", async (req: any, res: any) => {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  let payload: any;
  try {
    payload = jwt.verify(auth, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }

  const { link, limit, chunkSize = 40, cooldown = 10, concurrency = 50 } = req.body;
  if (!link || !limit || typeof limit !== "number") return res.status(400).json({ error: "link and numeric limit required" });

  const tokens = await readTokens();
  if (!tokens || tokens.length === 0) return res.status(400).json({ error: "no tokens available — add cookies first" });

  const users = await readUsers();
  const userIdx = users.findIndex((u) => u.id === payload.id);
  if (userIdx === -1) return res.status(401).json({ error: "user not found" });
  const user = users[userIdx];

  let bypassCooldown = false;
  if (user.isPremium) bypassCooldown = true;
  else if ((user.trialRemaining ?? 0) > 0) {
    bypassCooldown = true;
    users[userIdx].trialRemaining = (users[userIdx].trialRemaining ?? 0) - 1;
    await writeUsers(users);
  }

  const jobId = `job-${uuidv4()}`;
  const io = (req.app.locals.io as import("socket.io").Server);

  io.to(jobId).emit("log", { level: "info", message: `User ${user.username} started job ${jobId}` });

  startShareJob({ jobId, link, limit, chunkSize, cooldown, concurrency, tokens, io, bypassCooldown })
    .catch((err) => {
      io.to(jobId).emit("log", { level: "error", message: `Job error: ${String(err)}` });
    });

  res.json({ ok: true, jobId, bypassCooldown, trialRemaining: users[userIdx].trialRemaining });
});

export default router;
EOF

# ensure data dir exists and gitkeep
mkdir -p backend/data
cat > backend/data/.gitkeep <<'EOF'
# keep data folder
EOF

####################################
# Frontend files
####################################

cat > frontend/package.json <<'EOF'
{
  "name": "fb-autoshare-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.5.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "socket.io-client": "^4.7.2",
    "jwt-decode": "^3.1.2",
    "react-router-dom": "^6.14.2"
  },
  "devDependencies": {
    "@types/react": "^18.2.21",
    "@types/react-dom": "^18.2.7",
    "@types/react-router-dom": "^5.3.3",
    "tailwindcss": "^3.5.5",
    "autoprefixer": "^10.4.14",
    "postcss": "^8.4.27",
    "typescript": "^5.4.2",
    "vite": "^5.1.7",
    "@vitejs/plugin-react": "^4.0.0"
  }
}
EOF

cat > frontend/vite.config.ts <<'EOF'
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173
  }
});
EOF

cat > frontend/tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["DOM", "ES2020"],
    "module": "ESNext",
    "moduleResolution": "Node",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src"]
}
EOF

cat > frontend/.env.example <<'EOF'
# Copy to .env and set API URL for production if needed
VITE_API_URL=http://localhost:4000
EOF

cat > frontend/index.html <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>FB AutoSharer</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
EOF

cat > frontend/src/main.tsx <<'EOF'
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles/index.css";

createRoot(document.getElementById("root")!).render(<App />);
EOF

cat > frontend/src/App.tsx <<'EOF'
import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Link, useNavigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import Dashboard from "./pages/Dashboard";
import AdminPanel from "./pages/AdminPanel";
import { getMe, logout, getTokenLocal } from "./utils/auth";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

function Nav({ user, setUser }: any) {
  const [open, setOpen] = useState(false);
  return (
    <nav className="bg-white shadow">
      <div className="max-w-6xl mx-auto px-4">
        <div className="flex justify-between">
          <div className="flex space-x-4">
            <div>
              <Link to="/" className="flex items-center py-5 px-2 text-gray-700">
                <span className="font-bold text-lg">FB AutoSharer</span>
              </Link>
            </div>
            <div className="hidden md:flex items-center space-x-1">
              <Link to="/" className="py-5 px-3 text-gray-700 hover:text-gray-900">Dashboard</Link>
              {user?.isAdmin && <Link to="/admin" className="py-5 px-3 text-gray-700 hover:text-gray-900">Admin</Link>}
            </div>
          </div>
          <div className="hidden md:flex items-center space-x-1">
            {user ? (
              <>
                <div className="py-2 px-3 text-sm text-gray-700">Hi, {user.username}</div>
                <button className="py-2 px-3 bg-red-600 text-white rounded" onClick={() => { logout(); setUser(null); }}>
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="py-2 px-3 bg-blue-600 text-white rounded">Login</Link>
              </>
            )}
          </div>
          <div className="md:hidden flex items-center">
            <button onClick={() => setOpen(!open)} className="mobile-menu-button p-2">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16"/>
              </svg>
            </button>
          </div>
        </div>
      </div>
      {open && (
        <div className="md:hidden">
          <Link to="/" className="block py-2 px-4">Dashboard</Link>
        </div>
      )}
    </nav>
  );
}

export default function App() {
  const [user, setUser] = useState<any | null>(null);

  useEffect(() => {
    const token = getTokenLocal();
    if (token) {
      getMe(token).then((u) => setUser(u)).catch(() => setUser(null));
    }
  }, []);

  return (
    <BrowserRouter>
      <Nav user={user} setUser={setUser} />
      <div className="container mx-auto p-6">
        <Routes>
          <Route path="/" element={<Dashboard user={user} setUser={setUser} api={API} />} />
          <Route path="/login" element={<LoginPage setUser={setUser} api={API} />} />
          <Route path="/register" element={<RegisterPage setUser={setUser} api={API} />} />
          <Route path="/admin" element={<AdminPanel user={user} api={API} />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
EOF

cat > frontend/src/utils/auth.ts <<'EOF'
import axios from "axios";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:4000";
const TOKEN_KEY = "fb_autoshare_token";

export function setTokenLocal(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getTokenLocal(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function loginRequest(api: string, username: string, password: string) {
  const res = await axios.post(`${api}/api/auth/login`, { username, password });
  return res.data;
}

export async function registerRequest(api: string, username: string, password: string) {
  const res = await axios.post(`${api}/api/auth/register`, { username, password });
  return res.data;
}

export async function getMe(token: string) {
  const res = await axios.get(`${API}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  return res.data.user;
}
EOF

cat > frontend/src/pages/LoginPage.tsx <<'EOF'
import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { loginRequest, setTokenLocal } from "../utils/auth";

export default function LoginPage({ setUser, api }: any) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  async function submit() {
    try {
      const data = await loginRequest(api, username, password);
      setTokenLocal(data.token);
      setUser(data.user);
      navigate("/");
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Login failed");
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white shadow p-6 rounded">
      <h2 className="text-xl font-semibold mb-4">Login</h2>
      <input className="w-full p-2 border rounded mb-2" placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" className="w-full p-2 border rounded mb-2" placeholder="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <div className="flex space-x-2">
        <button onClick={submit} className="px-4 py-2 bg-blue-600 text-white rounded">Login</button>
        <Link to="/register" className="px-4 py-2 bg-gray-200 rounded">Register</Link>
      </div>
    </div>
  );
}
EOF

cat > frontend/src/pages/RegisterPage.tsx <<'EOF'
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerRequest, setTokenLocal } from "../utils/auth";

export default function RegisterPage({ setUser, api }: any) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  async function submit() {
    try {
      const data = await registerRequest(api, username, password);
      setTokenLocal(data.token);
      setUser(data.user);
      navigate("/");
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Register failed");
    }
  }

  return (
    <div className="max-w-md mx-auto bg-white shadow p-6 rounded">
      <h2 className="text-xl font-semibold mb-4">Register</h2>
      <input className="w-full p-2 border rounded mb-2" placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" className="w-full p-2 border rounded mb-2" placeholder="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <div className="flex space-x-2">
        <button onClick={submit} className="px-4 py-2 bg-green-600 text-white rounded">Register</button>
      </div>
    </div>
  );
}
EOF

cat > frontend/src/pages/Dashboard.tsx <<'EOF'
import React, { useEffect, useState, useRef } from "react";
import axios from "axios";
import io from "socket.io-client";

export default function Dashboard({ user, setUser, api }: any) {
  const [cookiesText, setCookiesText] = useState("");
  const [tokens, setTokens] = useState<any[]>([]);
  const [link, setLink] = useState("");
  const [limit, setLimit] = useState(100);
  const [logs, setLogs] = useState<string[]>([]);
  const socketRef = useRef<any>(null);

  useEffect(() => {
    fetchTokens();
    return () => { if (socketRef.current) socketRef.current.disconnect(); };
  }, []);

  async function fetchTokens() {
    try {
      const res = await axios.get(`${api}/api/auth/tokens`);
      setTokens(res.data.tokens ?? []);
    } catch (err) {
      console.error(err);
    }
  }

  async function uploadCookies() {
    const lines = cookiesText.split("\n").map(s => s.trim()).filter(Boolean);
    if (lines.length === 0) return alert("Paste cookies one per line");
    try {
      const res = await axios.post(`${api}/api/auth/cookies`, { cookies: lines });
      pushLog("Upload results: " + JSON.stringify(res.data.results));
      setCookiesText("");
      fetchTokens();
    } catch (err: any) {
      pushLog("Upload error: " + (err.message ?? JSON.stringify(err)));
    }
  }

  function pushLog(line: string) {
    setLogs(s => [line, ...s].slice(0, 500));
  }

  async function startShare() {
    if (!link || limit <= 0) return alert("Provide link and positive limit");
    const token = localStorage.getItem("fb_autoshare_token");
    if (!token) return alert("Login first");
    try {
      const res = await axios.post(`${api}/api/share/start`, { link, limit }, { headers: { Authorization: `Bearer ${token}` } });
      const jobId = res.data.jobId;
      pushLog(`Job started: ${jobId} (bypassCooldown=${res.data.bypassCooldown})`);
      const socket = io(api);
      socketRef.current = socket;
      socket.emit("join", jobId);
      socket.on("log", (data: any) => pushLog(JSON.stringify(data)));
      socket.on("done", (d: any) => {
        pushLog("Job done: " + JSON.stringify(d));
        socket.disconnect();
      });
    } catch (err: any) {
      pushLog("Start error: " + (err.response?.data?.error ?? err.message));
    }
  }

  return (
    <div>
      <div className="grid md:grid-cols-3 gap-4">
        <div className="col-span-2 bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">Share Job</h2>
          <div className="mb-2">
            <input value={link} onChange={(e) => setLink(e.target.value)} placeholder="https://facebook.com/..." className="w-full border p-2 rounded" />
          </div>
          <div className="flex items-center gap-2 mb-2">
            <input type="number" value={limit} onChange={(e) => setLimit(Number(e.target.value))} className="w-40 border p-2 rounded" />
            <button onClick={startShare} className="px-4 py-2 bg-green-600 text-white rounded">Start Share</button>
          </div>
          <div className="text-sm text-gray-600">
            Your status: {user ? `${user.username}` : "not logged in"} — {user?.isPremium ? "Premium" : `Trial remaining: ${user?.trialRemaining ?? 0}`}
          </div>

          <div className="mt-4">
            <h3 className="font-semibold">Logs</h3>
            <div className="bg-black text-green-200 p-3 rounded h-64 overflow-auto text-xs">
              {logs.map((l, i) => <div key={i}>{l}</div>)}
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-lg font-semibold mb-2">Upload Cookies</h2>
          <textarea value={cookiesText} onChange={(e) => setCookiesText(e.target.value)} placeholder="One cookie per line" className="w-full h-40 border p-2 rounded" />
          <div className="mt-2">
            <button onClick={uploadCookies} className="px-4 py-2 bg-blue-600 text-white rounded">Upload & Extract Tokens</button>
          </div>

          <div className="mt-4">
            <h3 className="font-semibold">Stored tokens ({tokens.length})</h3>
            <div className="h-40 overflow-auto bg-slate-50 p-2 rounded text-xs">
              {tokens.map((t: any, i: number) => <div key={i}>#{i+1}: {t.token.slice(0, 12)}... added {new Date(t.addedAt).toLocaleString()}</div>)}
            </div>
          </div>

          <div className="mt-4">
            <h3 className="font-semibold">Redeem Premium Code</h3>
            <RedeemForm api={api} onSuccess={(u: any) => { pushLog("Redeemed: " + JSON.stringify(u)); }} />
          </div>
        </div>
      </div>
    </div>
  );
}

function RedeemForm({ api, onSuccess }: any) {
  const [code, setCode] = useState("");
  function getToken() {
    return localStorage.getItem("fb_autoshare_token");
  }
  async function redeem() {
    const token = getToken();
    if (!token) return alert("Login first");
    try {
      const res = await axios.post(`${api}/api/auth/redeem`, { code, auth: token });
      onSuccess(res.data);
      alert("Redeemed successfully");
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Redeem failed");
    }
  }
  return (
    <div>
      <input className="w-full border p-2 rounded mb-2" placeholder="CODE" value={code} onChange={(e) => setCode(e.target.value)} />
      <button onClick={redeem} className="px-3 py-2 bg-yellow-600 text-white rounded">Redeem</button>
    </div>
  );
}
EOF

cat > frontend/src/pages/AdminPanel.tsx <<'EOF'
import React, { useEffect, useState } from "react";
import axios from "axios";
import { getTokenLocal } from "../utils/auth";
import { useNavigate } from "react-router-dom";

export default function AdminPanel({ user, api }: any) {
  const [codes, setCodes] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [count, setCount] = useState(1);
  const [newAdminUser, setNewAdminUser] = useState("");
  const [newAdminPass, setNewAdminPass] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    if (!user || !user.isAdmin) {
      navigate("/");
      return;
    }
    fetchCodes();
    fetchUsers();
  }, []);

  function tokenHeader() {
    const t = getTokenLocal();
    return { headers: { Authorization: `Bearer ${t}` } };
  }

  async function fetchCodes() {
    try {
      const res = await axios.get(`${api}/api/admin/codes`, tokenHeader());
      setCodes(res.data.codes ?? []);
    } catch (err) {
      console.error(err);
    }
  }

  async function fetchUsers() {
    try {
      const res = await axios.get(`${api}/api/admin/users`, tokenHeader());
      setUsers(res.data.users ?? []);
    } catch (err) {
      console.error(err);
    }
  }

  async function createCodes() {
    try {
      const res = await axios.post(`${api}/api/admin/codes`, { count }, tokenHeader());
      fetchCodes();
      alert(`Created ${count} codes`);
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Error");
    }
  }

  async function changeAdmin() {
    try {
      await axios.post(`${api}/api/admin/change-admin`, { newUsername: newAdminUser || undefined, newPassword: newAdminPass || undefined }, tokenHeader());
      alert("Admin credentials updated. You may need to log in with new credentials.");
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Error");
    }
  }

  return (
    <div className="max-w-4xl mx-auto bg-white p-6 rounded shadow">
      <h2 className="text-xl font-semibold mb-4">Admin Panel</h2>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="p-4 border rounded">
          <h3 className="font-semibold mb-2">Generate Premium Codes</h3>
          <div className="flex gap-2 mb-2">
            <input type="number" className="p-2 border rounded w-24" value={count} onChange={(e) => setCount(Number(e.target.value))} />
            <button onClick={createCodes} className="px-3 py-2 bg-blue-600 text-white rounded">Create</button>
          </div>
          <div className="text-sm">
            <h4 className="font-medium">Existing Codes</h4>
            <div className="max-h-48 overflow-auto bg-slate-50 p-2 rounded">
              {codes.map((c: any, i: number) => <div key={i}>{c.code} — created by {c.createdBy} {c.redeemedBy ? ` — redeemed by ${c.redeemedBy}` : ""}</div>)}
            </div>
          </div>
        </div>

        <div className="p-4 border rounded">
          <h3 className="font-semibold mb-2">Admin Credentials</h3>
          <input className="w-full p-2 border rounded mb-2" placeholder="New admin username" value={newAdminUser} onChange={(e) => setNewAdminUser(e.target.value)} />
          <input className="w-full p-2 border rounded mb-2" placeholder="New admin password" value={newAdminPass} onChange={(e) => setNewAdminPass(e.target.value)} />
          <button onClick={changeAdmin} className="px-3 py-2 bg-red-600 text-white rounded">Change Admin Creds</button>
        </div>
      </div>

      <div className="mt-4 p-4 border rounded">
        <h3 className="font-semibold mb-2">Users</h3>
        <div className="max-h-48 overflow-auto">
          {users.map((u: any, i: number) => (
            <div key={i} className="p-2 border-b">
              {u.username} — {u.isAdmin ? "Admin" : "User"} — Premium: {u.isPremium ? "Yes" : "No"} — Trials: {u.trialRemaining}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
EOF

cat > frontend/src/styles/index.css <<'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

html, body, #root {
  height: 100%;
  background: #f8fafc;
  font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}

.container {
  max-width: 1100px;
}
EOF

cat > frontend/postcss.config.cjs <<'EOF'
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
EOF

cat > frontend/tailwind.config.cjs <<'EOF'
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
};
EOF

cat > frontend/Dockerfile <<'EOF'
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:stable-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
EOF

echo "All files created. Now creating zip archive: $ZIP_NAME"

# create the zip, excluding node_modules, .git, and backend data json files
# ensure zip is available
if ! command -v zip >/dev/null 2>&1; then
  echo "zip command not found. Creating tar.gz instead as fallback: ${ZIP_NAME%.zip}.tar.gz"
  tar --exclude='node_modules' --exclude='.git' --exclude='backend/data/*.json' -czf "${ZIP_NAME%.zip}.tar.gz" .
  echo "Archive created: ${ROOT_DIR}/${ZIP_NAME%.zip}.tar.gz"
else
  zip -r "$ZIP_NAME" . -x "node_modules/*" ".git/*" "backend/data/*.json" "*.DS_Store"
  echo "Archive created: ${ROOT_DIR}/${ZIP_NAME}"
fi

echo "Done. Project and archive are available in: $ROOT_DIR"
echo "Next steps:"
echo "  cd $ROOT_DIR"
echo "  # Install dependencies (backend & frontend) when ready:"
echo "  # cd backend && npm install"
echo "  # cd ../frontend && npm install"
echo ""
echo "Remember to create a .env in backend/ from .env.example and set JWT_SECRET (and others) before running."