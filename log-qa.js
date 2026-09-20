import { json, getUser, getPerms, ensureSchema, purgeOldLogs } from "../_utils.js";

// Ghi nhật ký cho Lớp 1 (tra cứu không AI, chạy ở client). Endpoint này không trả về nội dung
// nghiệp vụ nào — chỉ dùng để admin theo dõi lịch sử sử dụng. Client gọi ngầm (fire-and-forget),
// lỗi ở đây không được phép ảnh hưởng đến trải nghiệm tra cứu của người dùng.
export async function onRequestPost({ request, env, waitUntil }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const p = await getPerms(env, u.id);
  if (!p.can_qa) return json({ error: "forbidden" }, 403);

  const { cau_hoi, so_can_cu } = await request.json().catch(() => ({}));
  const text = String(cau_hoi || "").trim().slice(0, 4000);
  // Lớp phòng thủ: không ghi dòng L1 nào nếu không có nội dung câu hỏi thật (ví dụ body rỗng do lỗi
  // mạng/client gửi thiếu) — tránh làm phình nhật ký với các dòng rỗng vô nghĩa.
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
