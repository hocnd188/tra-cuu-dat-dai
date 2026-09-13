import { json, getUser, hashPassword, ensureSchema } from "../../_utils.js";
export async function onRequestDelete({ request, env, params }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const id = parseInt(params.id, 10);
  if (id === u.id) return json({ error: "Không thể tự xóa chính mình" }, 400);
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  return json({ ok: true });
}
export async function onRequestPut({ request, env, params }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  await ensureSchema(env);
  const id = parseInt(params.id, 10);
  const body = await request.json().catch(() => ({}));
  // Cập nhật quyền (can_qa / can_ai) nếu có gửi
  if (body.can_qa !== undefined || body.can_ai !== undefined) {
    if (body.can_qa !== undefined)
      await env.DB.prepare("UPDATE users SET can_qa = ? WHERE id = ?").bind(body.can_qa ? 1 : 0, id).run();
    if (body.can_ai !== undefined)
      await env.DB.prepare("UPDATE users SET can_ai = ? WHERE id = ?").bind(body.can_ai ? 1 : 0, id).run();
    return json({ ok: true });
  }
  // Đổi mật khẩu
  const { password } = body;
  if (!password || password.length < 6) return json({ error: "Mật khẩu ≥ 6 ký tự" }, 400);
  const { salt, hash } = await hashPassword(password);
  await env.DB.prepare("UPDATE users SET salt = ?, hash = ? WHERE id = ?").bind(salt, hash, id).run();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
  return json({ ok: true });
}
