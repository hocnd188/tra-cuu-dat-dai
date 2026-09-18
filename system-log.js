import { json, getUser, ensureSchema, purgeOldLogs } from "../_utils.js";

// Nhật ký hệ thống dành riêng cho admin: lịch sử đăng nhập (ngày giờ, ai) và lịch sử hỏi-đáp
// đầy đủ nội dung (cả Lớp 1 không AI và Lớp 2 có AI). Không có UI công khai nào gọi endpoint
// này ngoài khu vực ẩn trong admin.html — người dùng thường không biết và không thấy dấu vết.
//
// Query params (đều tùy chọn):
//   kind      = "access" | "qa"  (mặc định "qa")
//   user      = lọc theo username (khớp gần đúng, không phân biệt hoa/thường)
//   from, to  = lọc theo ngày, định dạng YYYY-MM-DD (theo cột ts, so sánh chuỗi ISO)
//   q         = từ khóa tìm trong nội dung câu hỏi (chỉ áp dụng khi kind=qa)
//   layer     = "L1" | "L2" (chỉ áp dụng khi kind=qa)
//   page      = số trang (bắt đầu từ 1), page_size mặc định 50, tối đa 200
export async function onRequestGet({ request, env, waitUntil }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);

  if (typeof waitUntil === "function") waitUntil(purgeOldLogs(env, 90));

  const url = new URL(request.url);
  const kind = (url.searchParams.get("kind") || "qa").toLowerCase();
  const userFilter = (url.searchParams.get("user") || "").trim();
  const from = (url.searchParams.get("from") || "").trim();
  const to = (url.searchParams.get("to") || "").trim();
  const qKw = (url.searchParams.get("q") || "").trim();
  const layer = (url.searchParams.get("layer") || "").trim().toUpperCase();
  let page = parseInt(url.searchParams.get("page") || "1", 10); if (!page || page < 1) page = 1;
  let pageSize = parseInt(url.searchParams.get("page_size") || "50", 10);
  if (!pageSize || pageSize < 1) pageSize = 50;
  if (pageSize > 200) pageSize = 200;
  const offset = (page - 1) * pageSize;

  const table = kind === "access" ? "access_log" : (kind === "debug" ? "debug_errors" : "ai_usage");
  const where = [];
  const binds = [];
  if (userFilter && kind !== "debug") { where.push("LOWER(username) LIKE ?"); binds.push("%" + userFilter.toLowerCase() + "%"); }
  if (from) { where.push("ts >= ?"); binds.push(from + "T00:00:00.000Z"); }
  if (to) { where.push("ts <= ?"); binds.push(to + "T23:59:59.999Z"); }
  if (kind === "qa" && qKw) { where.push("LOWER(cau_hoi) LIKE ?"); binds.push("%" + qKw.toLowerCase() + "%"); }
  if (kind === "qa" && (layer === "L1" || layer === "L2")) { where.push("layer = ?"); binds.push(layer); }
  const whereSql = where.length ? ("WHERE " + where.join(" AND ")) : "";

  const cols = kind === "access"
    ? "id, user_id, username, ts, ip, ua"
    : (kind === "debug" ? "id, ts, noi_dung, chi_tiet" : "id, user_id, username, ts, cau_hoi, model, ok, layer");

  const countRow = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} ${whereSql}`).bind(...binds).first();
  const total = (countRow && countRow.n) || 0;

  const rs = await env.DB.prepare(
    `SELECT ${cols} FROM ${table} ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`
  ).bind(...binds, pageSize, offset).all();

  // Vài số liệu tổng quan nhanh để hiển thị đầu trang
  const today = new Date().toISOString().slice(0, 10);
  const todayAccess = await env.DB.prepare("SELECT COUNT(*) AS n FROM access_log WHERE substr(ts,1,10) = ?").bind(today).first();
  // layer='0' = dòng "chỉ truy cập, không hỏi đáp" (xem logAccessAsQa trong _utils.js) — không tính
  // vào số "hỏi đáp N lượt" hiển thị đầu trang, chỉ hiện trong bảng chi tiết bên dưới.
  const todayQa = await env.DB.prepare("SELECT COUNT(*) AS n FROM ai_usage WHERE substr(ts,1,10) = ? AND layer != '0'").bind(today).first();
  const todayErr = await env.DB.prepare("SELECT COUNT(*) AS n FROM debug_errors WHERE substr(ts,1,10) = ?").bind(today).first();

  return json({
    kind, page, page_size: pageSize, total,
    rows: rs.results || [],
    today_access: (todayAccess && todayAccess.n) || 0,
    today_qa: (todayQa && todayQa.n) || 0,
    today_err: (todayErr && todayErr.n) || 0,
  });
}
