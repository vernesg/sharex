// backend/src/routes/auth.ts
import express from "express";
import { readTokens, writeTokens, readUsers, writeUsers, User, readCodes, writeCodes } from "../storage";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();

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
      trialRemaining: 0,
      sessionToken: undefined
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
  const sessionToken = uuidv4();
  const newUser: User = { id: uuidv4(), username, passwordHash: hash, isAdmin: false, isPremium: false, trialRemaining: 3, sessionToken };
  users.push(newUser);
  await writeUsers(users);
  res.json({ token: sessionToken, user: { id: newUser.id, username: newUser.username, isPremium: newUser.isPremium, trialRemaining: newUser.trialRemaining, isAdmin: newUser.isAdmin } });
});

// login
router.post("/login", async (req, res) => {
  await ensureAdminSeed();
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const users = await readUsers();
  const userIdx = users.findIndex((u) => u.username === username);
  if (userIdx === -1) return res.status(400).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, users[userIdx].passwordHash);
  if (!ok) return res.status(400).json({ error: "invalid credentials" });
  const sessionToken = uuidv4();
  users[userIdx].sessionToken = sessionToken;
  await writeUsers(users);
  const user = users[userIdx];
  res.json({ token: sessionToken, user: { id: user.id, username: user.username, isPremium: user.isPremium, trialRemaining: user.trialRemaining, isAdmin: user.isAdmin } });
});

// logout
router.post("/logout", async (req, res) => {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.json({ ok: true });
  const users = await readUsers();
  const userIdx = users.findIndex((u) => u.sessionToken === auth);
  if (userIdx >= 0) {
    users[userIdx].sessionToken = undefined;
    await writeUsers(users);
  }
  res.json({ ok: true });
});

// get me
router.get("/me", async (req, res) => {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  try {
    const users = await readUsers();
    const user = users.find((u) => u.sessionToken === auth);
    if (!user) return res.status(401).json({ error: "user not found" });
    res.json({ user: { id: user.id, username: user.username, isPremium: user.isPremium, trialRemaining: user.trialRemaining, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(401).json({ error: "invalid token" });
  }
});

/**
 * POST /api/auth/cookies
 * body: { cookies: string[] }
 *
 * Accepts one or more raw cookie strings (e.g. "c_user=...; xs=...;"), attempts to extract EAAG token,
 * stores token+cookie pairs in data/tokens.json and returns results.
 */
router.post("/cookies", async (req, res) => {
  const cookies: string[] = req.body.cookies;
  if (!Array.isArray(cookies) || cookies.length === 0) return res.status(400).json({ error: "cookies must be a non-empty array" });
  const tokens = await readTokens();
  const results: any[] = [];
  const { extractTokenFromFacebook, parseCookieString } = require("../utils/facebook"); // dynamic import to avoid TS issues

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

// list tokens
router.get("/tokens", async (_req, res) => {
  const tokens = await readTokens();
  res.json({ tokens });
});

// redeem code
router.post("/redeem", async (req, res) => {
  const { code, token } = req.body; // here token = session token
  if (!code) return res.status(400).json({ error: "code required" });
  if (!token) return res.status(401).json({ error: "auth token required" });
  try {
    const users = await readUsers();
    const userIdx = users.findIndex((u) => u.sessionToken === token);
    if (userIdx === -1) return res.status(401).json({ error: "user not found" });
    const codes = await readCodes();
    const codeEntry = codes.find((c) => c.code === code && !c.redeemedBy);
    if (!codeEntry) return res.status(400).json({ error: "invalid or already redeemed code" });
    users[userIdx].isPremium = true;
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