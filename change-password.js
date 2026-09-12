import { json, getUser, hashPassword, verifyPassword } from "../_utils.js";
export async function onRequestPut({ request, env }) {
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const { current_password, new_password } = await request.json().catch(() => ({}));
  if (!current_password || !new_password)
    return json({ error: "Cần nhập mật khẩu hiện tại và mật khẩu mới" }, 400);
  if (new_password.length < 6)
    return json({ error: "Mật khẩu mới phải từ 6 ký tự trở lên" }, 400);
  const row = await env.DB.prepare("SELECT salt, hash FROM users WHERE id = ?").bind(u.id).first();
  if (!row) return json({ error: "Không tìm thấy tài khoản" }, 404);
  const ok = await verifyPassword(current_password, row.salt, row.hash);
  if (!ok) return json({ error: "Mật khẩu hiện tại không đúng" }, 401);
  const { salt, hash } = await hashPassword(new_password);
  await env.DB.prepare("UPDATE users SET salt = ?, hash = ? WHERE id = ?").bind(salt, hash, u.id).run();
  // Đăng xuất tất cả phiên khác (giữ lại phiên hiện tại đang dùng để đổi) vì mật khẩu vừa đổi
  const cookieToken = (request.headers.get("Cookie") || "").match(/(?:^|; )session=([^;]+)/);
  const keepToken = cookieToken ? decodeURIComponent(cookieToken[1]) : null;
  if (keepToken) {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?").bind(u.id, keepToken).run();
  } else {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id).run();
  }
  return json({ ok: true });
}
