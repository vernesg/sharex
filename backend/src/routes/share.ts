// backend/src/routes/share.ts
import express from "express";
import { readTokens, readUsers, writeUsers } from "../storage";
import { startShareJob } from "../utils/facebook";
import { v4 as uuidv4 } from "uuid";

const router = express.Router();

router.post("/start", async (req: any, res: any) => {
  const auth = req.headers.authorization?.split(" ")[1];
  if (!auth) return res.status(401).json({ error: "not authenticated" });
  let payloadUser: any = null;

  const users = await readUsers();
  const userIdx = users.findIndex((u) => u.sessionToken === auth);
  if (userIdx === -1) return res.status(401).json({ error: "user not found" });
  const user = users[userIdx];

  const { link, limit, chunkSize = 40, cooldown = 10, concurrency = 50 } = req.body;
  if (!link || !limit || typeof limit !== "number") return res.status(400).json({ error: "link and numeric limit required" });

  const tokens = await readTokens();
  if (!tokens || tokens.length === 0) return res.status(400).json({ error: "no tokens available — add cookies first" });

  // Determine bypassCooldown: premium or user uses trialRemaining > 0 (consume one trial)
  let bypassCooldown = false;
  if (user.isPremium) bypassCooldown = true;
  else if ((user.trialRemaining ?? 0) > 0) {
    bypassCooldown = true;
    users[userIdx].trialRemaining = (users[userIdx].trialRemaining ?? 0) - 1;
    await writeUsers(users);
  }

  const jobId = `job-${uuidv4()}`;
  const io = (req.app.locals.io as import("socket.io").Server);

  // run the job asynchronously
  startShareJob({ jobId, link, limit, chunkSize, cooldown, concurrency, tokens, io, bypassCooldown }).catch((err) => {
    io.to(jobId).emit("log", { level: "error", message: `Job error: ${String(err)}` });
  });

  res.json({ ok: true, jobId, bypassCooldown, trialRemaining: users[userIdx].trialRemaining });
});

export default router;