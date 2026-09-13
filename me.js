import { json, getUser, getPerms } from "../_utils.js";
export async function onRequestGet({ request, env }) {
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const p = await getPerms(env, u.id);
  return json({
    id: u.id,
    username: u.username,
    is_admin: u.is_admin,
    can_qa: p.can_qa,        // quyền dùng Mục hỏi đáp (Lớp 1)
    can_ai: p.can_ai,        // quyền dùng AI (Lớp 2)
    u: u.username,           // tương thích footer cũ
    r: u.is_admin ? "admin" : "user",
  });
}
