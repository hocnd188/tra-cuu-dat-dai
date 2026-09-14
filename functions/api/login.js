import { json, verifyPassword, newToken, sessionCookie, logAccess, purgeOldLogs, ensureSchema } from "../_utils.js";
export async function onRequestPost({ request, env, waitUntil }) {
  await ensureSchema(env);
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return json({ error: "Thiếu thông tin" }, 400);
  const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  if (!u) return json({ error: "Sai tài khoản hoặc mật khẩu" }, 401);
  const ok = await verifyPassword(password, u.salt, u.hash);
  if (!ok) return json({ error: "Sai tài khoản hoặc mật khẩu" }, 401);
  const token = newToken();
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)")
    .bind(token, u.id, exp).run();
  // Ghi nhật ký truy cập chạy nền (waitUntil giữ cho tác vụ chạy xong dù response đã trả về;
  // không await để không làm chậm phản hồi đăng nhập của user).
  if (typeof waitUntil === "function") {
    waitUntil(logAccess(env, request, u.id, u.username));
    waitUntil(purgeOldLogs(env, 90));
  } else {
    logAccess(env, request, u.id, u.username);
    purgeOldLogs(env, 90);
  }
  return json({ ok: true, is_admin: !!u.is_admin }, 200, { "Set-Cookie": sessionCookie(token, exp) });
}
