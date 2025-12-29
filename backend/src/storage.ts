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