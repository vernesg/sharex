// frontend/src/utils/auth.ts
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
  const t = getTokenLocal();
  if (t) {
    try {
      axios.post(`${API}/api/auth/logout`, {}, { headers: { Authorization: `Bearer ${t}` } }).catch(()=>{});
    } catch {}
  }
  localStorage.removeItem(TOKEN_KEY);
}

export async function loginRequest(api: string, username: string, password: string) {
  const res = await axios.post(`${api}/api/auth/login`, { username, password });
  return res.data; // { token, user }
}

export async function registerRequest(api: string, username: string, password: string) {
  const res = await axios.post(`${api}/api/auth/register`, { username, password });
  return res.data;
}

export async function getMe(token: string) {
  const res = await axios.get(`${API}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  return res.data.user;
}