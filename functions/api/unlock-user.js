import { json, getUser, ensureSchema, listLockedUsers, adminUnlockUser } from "../_utils.js";

// GET  -> trả danh sách tài khoản đang bị khóa cứng
// POST -> mở khóa 1 tài khoản, body: { username }
// Chỉ admin được gọi cả hai.
export async function onRequestGet({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const rows = await listLockedUsers(env);
  return json({ rows });
}

export async function onRequestPost({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const { username } = await request.json().catch(() => ({}));
  if (!username) return json({ error: "Thiếu tên tài khoản" }, 400);
  await adminUnlockUser(env, username);
  return json({ ok: true });
}
