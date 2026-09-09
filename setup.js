import { json, hashPassword, ensureSchema } from "../_utils.js";
export async function onRequestGet({ env }) {
  await ensureSchema(env);
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  return json({ needsSetup: (c?.n || 0) === 0 });
}
export async function onRequestPost({ request, env }) {
  await ensureSchema(env);
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  if ((c?.n || 0) !== 0) return json({ error: "Đã có tài khoản, không thể tạo admin lần nữa" }, 403);
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password || password.length < 6)
    return json({ error: "Cần username và mật khẩu ≥ 6 ký tự" }, 400);
  const { salt, hash } = await hashPassword(password);
  await env.DB.prepare(
    "INSERT INTO users(username,salt,hash,is_admin,created_at) VALUES(?,?,?,1,?)"
  ).bind(username, salt, hash, new Date().toISOString()).run();
  return json({ ok: true });
}
