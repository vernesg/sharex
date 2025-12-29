import express from "express";
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

// register
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

// login
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

// get me
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

/**
 * POST /api/auth/tokens
 * body: { tokens: string[] }
 *
 * Accepts one or more raw access tokens (Graph API access tokens).
 * Stores tokens in backend/data/tokens.json (token + addedAt).
 *
 * Note: This endpoint does NOT accept or store cookies.
 */
router.post("/tokens", async (req, res) => {
  const tokensInput: string[] = req.body.tokens;
  if (!Array.isArray(tokensInput) || tokensInput.length === 0) return res.status(400).json({ error: "tokens must be a non-empty array" });

  const tokens = await readTokens();
  const results: Array<{ token: string; ok: boolean; error?: string }> = [];

  for (const t of tokensInput) {
    const token = String(t).trim();
    if (!token) {
      results.push({ token, ok: false, error: "empty token" });
      continue;
    }
    // Optionally, we could validate token format here; for now we store it as provided.
    tokens.push({ token, addedAt: new Date().toISOString() });
    results.push({ token, ok: true });
  }

  await writeTokens(tokens);
  res.json({ results, total: tokens.length });
});

// list tokens
router.get("/tokens", async (_req, res) => {
  const tokens = await readTokens();
  res.json({ tokens });
});

// redeem code
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
    // redeem: set user premium and mark code used
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