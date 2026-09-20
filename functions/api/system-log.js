import { json, getUser, ensureSchema, purgeOldLogs } from "../_utils.js";

export async function onRequestGet({ request, env, waitUntil }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);

  const url0 = new URL(request.url);

  if (url0.searchParams.get("action") === "clear") {
    try {
      const kind = url0.searchParams.get("clear_kind") || "";
      if (kind !== "access" && kind !== "qa" && kind !== "both") {
        return json({ error: "Thiếu hoặc sai tham số clear_kind (access | qa | both)" }, 400);
      }
      const day = (url0.searchParams.get("clear_date") || "").trim();
      if (day && !/^\d{4}-\d{2}-\d{2}$/.test(day)) {
        return json({ error: "Định dạng ngày không hợp lệ (cần YYYY-MM-DD)" }, 400);
      }

      let dayFromUtc = null, dayToUtc = null;
      if (day) {
        dayFromUtc = new Date(day + "T00:00:00.000+07:00").toISOString();
        dayToUtc = new Date(day + "T23:59:59.999+07:00").toISOString();
      }

      let deletedAccess = 0, deletedQa = 0;
      if (kind === "access" || kind === "both") {
        const stmt = day
          ? env.DB.prepare("DELETE FROM access_log WHERE ts >= ? AND ts <= ?").bind(dayFromUtc, dayToUtc)
          : env.DB.prepare("DELETE FROM access_log");
        const r = await stmt.run();
        deletedAccess = (r && r.meta && r.meta.changes) || 0;
      }
      if (kind === "qa" || kind === "both") {
        const stmt = day
          ? env.DB.prepare("DELETE FROM ai_usage WHERE ts >= ? AND ts <= ?").bind(dayFromUtc, dayToUtc)
          : env.DB.prepare("DELETE FROM ai_usage");
        const r = await stmt.run();
        deletedQa = (r && r.meta && r.meta.changes) || 0;
      }

      return json({ ok: true, deleted_access: deletedAccess, deleted_qa: deletedQa });
    } catch (e) {
      try {
        await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
          .bind(new Date().toISOString(), "system-log (xóa nhật ký, qua GET) thất bại", String(e && e.stack || e && e.message || e)).run();
      } catch (e2) {}
      return json({ error: "Lỗi khi xóa: " + String(e && e.message || e) }, 500);
    }
  }

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

  const today = new Date().toISOString().slice(0, 10);
  const todayAccess = await env.DB.prepare("SELECT COUNT(*) AS n FROM access_log WHERE substr(ts,1,10) = ?").bind(today).first();
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
