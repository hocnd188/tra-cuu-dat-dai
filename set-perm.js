import { json, getUser, ensureSchema } from "../_utils.js";
export async function onRequestPost({ request, env }) {
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  await ensureSchema(env);
  const body = await request.json().catch(() => ({}));
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
