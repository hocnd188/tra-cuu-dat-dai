import { json, getUser, hashPassword, ensureSchema } from "../../_utils.js";
export async function onRequestGet({ request, env }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  await ensureSchema(env);
  const rs = await env.DB.prepare(
    "SELECT id, username, is_admin, can_qa, can_ai, created_at FROM users ORDER BY id"
  ).all();
  return json({ users: rs.results || [] });
}
export async function onRequestPost({ request, env }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  await ensureSchema(env);
  const body = await request.json().catch(() => ({}));

  // Nhánh cấp/thu hồi quyền Hỏi đáp (can_qa) và Dùng AI (can_ai) cho user thường.
  // Dùng chung POST /api/users, phân biệt bằng action, để tránh mọi vấn đề với method PATCH/route [id].js.
  if (body.action === "set_perm") {
    const id = parseInt(body.id, 10);
    if (!id) return json({ error: "Thiếu id" }, 400);
    const target = await env.DB.prepare("SELECT id, is_admin FROM users WHERE id = ?").bind(id).first();
    if (!target) return json({ error: "Không tìm thấy người dùng" }, 404);
    if (target.is_admin) return json({ error: "Không thể tự đổi quyền của admin" }, 400);
    if (body.can_qa !== undefined)
      await env.DB.prepare("UPDATE users SET can_qa = ? WHERE id = ?").bind(body.can_qa ? 1 : 0, id).run();
    if (body.can_ai !== undefined)
      await env.DB.prepare("UPDATE users SET can_ai = ? WHERE id = ?").bind(body.can_ai ? 1 : 0, id).run();
    return json({ ok: true });
  }

  const { username, password, is_admin, can_qa, can_ai } = body;
  if (!username || !password || password.length < 6)
    return json({ error: "Cần username và mật khẩu ≥ 6 ký tự" }, 400);
  const ex = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (ex) return json({ error: "Username đã tồn tại" }, 409);
  const { salt, hash } = await hashPassword(password);
  await env.DB.prepare(
    "INSERT INTO users(username,salt,hash,is_admin,can_qa,can_ai,created_at) VALUES(?,?,?,?,?,?,?)"
  ).bind(username, salt, hash, is_admin ? 1 : 0, can_qa ? 1 : 0, can_ai ? 1 : 0, new Date().toISOString()).run();
  return json({ ok: true });
}
