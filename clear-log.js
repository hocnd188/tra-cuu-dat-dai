import { json, getUser, ensureSchema } from "../_utils.js";

// Xóa Nhật ký hệ thống theo lựa chọn của admin — không thể hoàn tác. Chỉ admin được gọi.
// Body JSON:
//   kind = "access" | "qa" | "both"   (bắt buộc) — xóa bảng đăng nhập, bảng hỏi đáp, hay cả hai
//   date = "YYYY-MM-DD"                (tùy chọn) — chỉ xóa đúng ngày đó; bỏ trống = xóa TOÀN BỘ
// Trả về số dòng đã xóa ở mỗi bảng để admin.html hiển thị xác nhận rõ ràng đã xóa bao nhiêu.
export async function onRequestPost({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);

  const { kind, date } = await request.json().catch(() => ({}));
  if (kind !== "access" && kind !== "qa" && kind !== "both") {
    return json({ error: "Thiếu hoặc sai tham số kind (access | qa | both)" }, 400);
  }
  const day = (date || "").trim();
  // Xác thực định dạng ngày nếu có, để tránh câu lệnh xóa sai phạm vi do dữ liệu đầu vào lạ
  if (day && !/^\d{4}-\d{2}-\d{2}$/.test(day)) {
    return json({ error: "Định dạng ngày không hợp lệ (cần YYYY-MM-DD)" }, 400);
  }

  let deletedAccess = 0, deletedQa = 0;
  try {
    if (kind === "access" || kind === "both") {
      const stmt = day
        ? env.DB.prepare("DELETE FROM access_log WHERE substr(ts,1,10) = ?").bind(day)
        : env.DB.prepare("DELETE FROM access_log");
      const r = await stmt.run();
      deletedAccess = (r && r.meta && r.meta.changes) || 0;
    }
    if (kind === "qa" || kind === "both") {
      const stmt = day
        ? env.DB.prepare("DELETE FROM ai_usage WHERE substr(ts,1,10) = ?").bind(day)
        : env.DB.prepare("DELETE FROM ai_usage");
      const r = await stmt.run();
      deletedQa = (r && r.meta && r.meta.changes) || 0;
    }
  } catch (e) {
    return json({ error: "Lỗi khi xóa: " + String(e && e.message || e) }, 500);
  }

  return json({ ok: true, deleted_access: deletedAccess, deleted_qa: deletedQa });
}
