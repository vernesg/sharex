import axios from "axios";
import pLimit from "p-limit";
import { TokenEntry } from "../storage";
import { Server } from "socket.io";

const UA_LIST = [
  "Mozilla/5.0 (Linux; Android 10; Wildfire E Lite Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/105.0.5195.136 Mobile Safari/537.36[FBAN/EMA;FBLC/en_US;FBAV/298.0.0.10.115;]",
  "Mozilla/5.0 (Linux; Android 11; KINGKONG 5 Pro Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/320.0.0.12.108;]",
  "Mozilla/5.0 (Linux; Android 11; G91 Pro Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/106.0.5249.126 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/325.0.1.4.108;]"
];

export async function shareOnce(token: string, link: string): Promise<{ ok: boolean; body: any }> {
  // If MOCK_FB=true then simulate a successful share without calling Facebook
  if (String(process.env.MOCK_FB).toLowerCase() === "true") {
    return { ok: true, body: { id: `mock-${Math.floor(Math.random() * 1e9)}` } };
  }

  const ua = UA_LIST[Math.floor(Math.random() * UA_LIST.length)];
  try {
    const url = `https://graph.facebook.com/v13.0/me/feed?link=${encodeURIComponent(link)}&published=0&access_token=${encodeURIComponent(token)}`;
    const res = await axios.post(url, null, {
      headers: {
        "User-Agent": ua
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
        const res = await shareOnce(chosen.token, link);
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
      // tiny yield to avoid tight loop
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  room.emit("log", { level: "info", message: `Job ${jobId} finished. Total attempts: ${count}` });
  room.emit("done", { jobId, total: count });
}