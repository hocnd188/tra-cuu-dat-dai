import { json, getUser, getPerms, ensureSchema, purgeOldLogs } from "../_utils.js";

// Ghi nhật ký cho Lớp 1 (tra cứu không AI, chạy ở client). Endpoint này không trả về nội dung
// nghiệp vụ nào — chỉ dùng để admin theo dõi lịch sử sử dụng. Client gọi ngầm (fire-and-forget),
// lỗi ở đây không được phép ảnh hưởng đến trải nghiệm tra cứu của người dùng.
//
// MỞ RỘNG: cũng nhận request với { ping: true } (không có cau_hoi) để ghi dấu "đã truy cập app"
// (layer="0") — dùng route NÀY (đã CHỨNG MINH chạy đúng trên production, thấy rõ trong Nhật ký hệ
// thống hiện tại) thay vì tạo endpoint mới (/api/ping, /api/me — cả hai đã thử và không hoạt động
// trên production dù test cục bộ đều qua, khả năng cao do đoán sai cấu trúc route/file thực tế mà
// Claude chưa từng được xem trực tiếp). Trường hợp "ping" KHÔNG yêu cầu quyền can_qa — bất kỳ ai đăng
// nhập thành công đều được ghi dấu truy cập, bất kể có quyền dùng Mục hỏi đáp hay không.
export async function onRequestPost({ request, env, waitUntil }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);

  const body = await request.json().catch(() => ({}));

  if (body.ping) {
    // Chế độ "chỉ đánh dấu truy cập app" — không cần quyền can_qa, không ghi nội dung câu hỏi.
    // Chống ghi trùng: chỉ ghi nếu CHƯA có dòng layer="0" của đúng user này trong 30 phút gần đây.
    try {
      const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString();
      const recent = await env.DB.prepare(
        "SELECT id FROM ai_usage WHERE user_id = ? AND layer = '0' AND ts > ? ORDER BY id DESC LIMIT 1"
      ).bind(u.id, cutoff).first();
      if (!recent) {
        await env.DB.prepare(
          "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
        ).bind(u.id, u.username, new Date().toISOString(), null, null, null, "", "0").run();
      }
    } catch (e) {
      try {
        await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
          .bind(new Date().toISOString(), "log-qa (ping) thất bại cho user_id=" + u.id + " username=" + u.username, String(e && e.message || e)).run();
      } catch (e2) {}
    }
    return json({ ok: true });
  }

  const p = await getPerms(env, u.id);
  if (!p.can_qa) return json({ error: "forbidden" }, 403);

  const { cau_hoi, so_can_cu } = body;
  const text = String(cau_hoi || "").trim().slice(0, 4000);
  // Lớp phòng thủ: không ghi dòng L1 nào nếu không có nội dung câu hỏi thật. Bảo vệ khỏi trường hợp
  // một request khác (ví dụ {ping:true} từ index.html) vô tình đến đây mà KHÔNG đi qua nhánh
  // if(body.ping) ở trên — ví dụ nếu phiên bản file này trên máy chủ chưa cập nhật nhánh đó (stale
  // file, đã từng xảy ra thật với chính dự án này) — cau_hoi sẽ luôn là undefined/rỗng và trước đây
  // bị ghi nhầm thành 1 dòng "L1" với nội dung rỗng mỗi lần trang tải, làm phình nhật ký sai sự thật.
  if (!text) return json({ error: "Thiếu nội dung câu hỏi" }, 400);
  const ghiChu = (so_can_cu !== undefined && so_can_cu !== null) ? ("so_can_cu=" + so_can_cu) : "";

  try {
    await env.DB.prepare(
      "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
    ).bind(u.id, u.username, new Date().toISOString(), text, null, 1, ghiChu, "L1").run();
  } catch (e) {
    try {
      await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
        .bind(new Date().toISOString(), "log-qa (L1) thất bại cho user_id=" + u.id + " username=" + u.username, String(e && e.message || e)).run();
    } catch (e2) {}
  }

  if (typeof waitUntil === "function") waitUntil(purgeOldLogs(env, 90));

  return json({ ok: true });
}
