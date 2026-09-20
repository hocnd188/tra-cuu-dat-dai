import { getUser, json, ensureSchema } from "./_utils.js";

// Ghi dấu "đã truy cập app" (layer="0" trong ai_usage) — đặt TẠI ĐÂY, trong middleware, thay vì một
// API riêng được gọi bằng fetch() từ JS phía client. Bốn cách tiếp cận trước (endpoint /api/ping
// riêng, ghi trong getUser(), nhánh trong log-qa.js, nhánh trong system-log.js — tất cả đều gọi qua
// fetch() sau khi trang đã tải) đều gặp đúng 1 triệu chứng lặp lại không rõ nguyên nhân dù đã đổi
// route/method nhiều lần. Cách này khác về bản chất: middleware chạy ở phía SERVER, TRƯỚC KHI bất kỳ
// byte HTML nào được gửi về trình duyệt — không có JS nào chạy, không có request riêng nào có thể bị
// mất mạng/bị hủy do đóng tab hay chuyển app giữa chừng, không phụ thuộc index.html có được cache hay
// không (đây chính là nghi ngờ hàng đầu cho các lần thất bại trước).
async function logVisit(request, env, user) {
  try {
    await ensureSchema(env);
    const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    const recent = await env.DB.prepare(
      "SELECT id FROM ai_usage WHERE user_id = ? AND layer = '0' AND ts > ? ORDER BY id DESC LIMIT 1"
    ).bind(user.id, cutoff).first();
    if (!recent) {
      await env.DB.prepare(
        "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(user.id, user.username, new Date().toISOString(), null, null, null, "", "0").run();
    }
  } catch (e) {
    try {
      await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
        .bind(new Date().toISOString(), "middleware logVisit thất bại cho user_id=" + user.id, String(e && e.message || e)).run();
    } catch (e2) {}
  }
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const p = new URL(request.url).pathname;
  const gated = (p === "/" || p === "/index.html" || p === "/admin.html");
  if (!gated) return next();
  let user = null;
  try { user = await getUser(request, env); } catch (e) { user = null; }
  if (!user) return Response.redirect(new URL("/login.html", request.url).toString(), 302);
  if (p === "/admin.html" && !user.is_admin) return Response.redirect(new URL("/", request.url).toString(), 302);
  // Chỉ ghi khi vào trang chính (không tính /admin.html — admin xem trang quản trị không phải "dùng
  // app"). Await đồng bộ TRƯỚC khi trả next() — đảm bảo chắc chắn ghi xong, đúng bài học đã rút ra
  // nhiều lần trong dự án này về việc "chạy nền không chờ" dễ bị runtime hủy giữa chừng.
  if (p === "/" || p === "/index.html") {
    await logVisit(request, env, user);
  }
  return next();
}
