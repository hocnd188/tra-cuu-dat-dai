import { json, getUser, hashPassword } from "../../_utils.js";
export async function onRequestGet({ request, env }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const rs = await env.DB.prepare(
    "SELECT id, username, is_admin, created_at FROM users ORDER BY id"
  ).all();
  return json({ users: rs.results || [] });
}
export async function onRequestPost({ request, env }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const { username, password, is_admin } = await request.json().catch(() => ({}));
  if (!username || !password || password.length < 6)
    return json({ error: "Cần username và mật khẩu ≥ 6 ký tự" }, 400);
  const ex = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (ex) return json({ error: "Username đã tồn tại" }, 409);
  const { salt, hash } = await hashPassword(password);
  await env.DB.prepare(
    "INSERT INTO users(username,salt,hash,is_admin,created_at) VALUES(?,?,?,?,?)"
  ).bind(username, salt, hash, is_admin ? 1 : 0, new Date().toISOString()).run();
  return json({ ok: true });
}
