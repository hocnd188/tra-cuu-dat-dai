import { json, verifyPassword, newToken, sessionCookie, logAccess, purgeOldLogs, ensureSchema, checkLoginLock, recordLoginFailure, clearLoginFailures } from "../_utils.js";
export async function onRequestPost({ request, env, waitUntil }) {
  await ensureSchema(env);
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return json({ error: "Thiếu thông tin" }, 400);

  // Chặn dò mật khẩu: nếu tài khoản này đã sai đủ 5 lần liên tiếp, khóa CỨNG cho tới khi admin mở lại.
  const isLocked = await checkLoginLock(env, username);
  if (isLocked) {
    return json({ error: "Tài khoản đã bị khóa do nhập sai mật khẩu quá 5 lần. Vui lòng liên hệ quản trị viên để được mở khóa." }, 423);
  }

  const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  if (!u) {
    // Ghi nhận ĐỒNG BỘ (await) trước khi trả response — bắt buộc để khóa có hiệu lực ngay lập tức,
    // ngăn kẻ tấn công gửi nhiều request song song "lọt qua" trước khi bộ đếm kịp cập nhật.
    await recordLoginFailure(env, username);
    return json({ error: "Sai tài khoản hoặc mật khẩu" }, 401);
  }
  const ok = await verifyPassword(password, u.salt, u.hash);
  if (!ok) {
    await recordLoginFailure(env, username);
    return json({ error: "Sai tài khoản hoặc mật khẩu" }, 401);
  }

  const token = newToken();
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)")
    .bind(token, u.id, exp).run();
  // Xóa bộ đếm sai NGAY (đồng bộ) khi đăng nhập đúng — không để sót nếu có thao tác nào sau đó lỗi.
  await clearLoginFailures(env, username);
  // Ghi nhật ký truy cập và dọn log cũ có thể chạy nền — không ảnh hưởng đến tính đúng của cơ chế khóa.
  if (typeof waitUntil === "function") {
    waitUntil(logAccess(env, request, u.id, u.username));
    waitUntil(purgeOldLogs(env, 90));
  } else {
    logAccess(env, request, u.id, u.username);
    purgeOldLogs(env, 90);
  }
  return json({ ok: true, is_admin: !!u.is_admin }, 200, { "Set-Cookie": sessionCookie(token, exp) });
}
