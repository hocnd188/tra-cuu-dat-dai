import { json, getUser } from "../_utils.js";
export async function onRequestGet({ request, env }) {
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  // Trả về cả hai kiểu tên trường để footer trong index.html luôn nhận đúng:
  // - id / username / is_admin  (kiểu chuẩn)
  // - u / r                     (footer cũ đọc u.u và u.r === 'admin')
  return json({
    id: u.id,
    username: u.username,
    is_admin: u.is_admin,
    u: u.username,
    r: u.is_admin ? "admin" : "user",
  });
}
