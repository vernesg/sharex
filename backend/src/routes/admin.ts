// backend/src/routes/admin.ts
import express from "express";
import { readCodes, writeCodes, readUsers, writeUsers } from "../storage";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcryptjs";

const router = express.Router();

// admin middleware using session token
async function requireAdmin(req: any, res: any, next: any) {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  const users = await readUsers();
  const user = users.find((u) => u.sessionToken === auth);
  if (!user || !user.isAdmin) return res.status(403).json({ error: "admin only" });
  req.user = user;
  next();
}

// list codes
router.get("/codes", requireAdmin, async (_req: any, res: any) => {
  const codes = await readCodes();
  res.json({ codes });
});

// create code
router.post("/codes", requireAdmin, async (req: any, res: any) => {
  const { count = 1 } = req.body;
  const codes = await readCodes();
  for (let i = 0; i < count; i++) {
    const code = uuidv4().replace(/-/g, "").slice(0, 10).toUpperCase();
    codes.push({ code, createdAt: new Date().toISOString(), createdBy: req.user.username });
  }
  await writeCodes(codes);
  res.json({ ok: true, created: count, codes: codes.slice(-count) });
});

// revoke code
router.post("/codes/revoke", requireAdmin, async (req: any, res: any) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code required" });
  const codes = await readCodes();
  const idx = codes.findIndex((c) => c.code === code && !c.redeemedBy);
  if (idx === -1) return res.status(404).json({ error: "code not found or already redeemed" });
  codes.splice(idx, 1);
  await writeCodes(codes);
  res.json({ ok: true });
});

// change admin creds
router.post("/change-admin", requireAdmin, async (req: any, res: any) => {
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

// list users
router.get("/users", requireAdmin, async (_req: any, res: any) => {
  const users = await readUsers();
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, isAdmin: u.isAdmin, isPremium: u.isPremium, trialRemaining: u.trialRemaining })) });
});

export default router;