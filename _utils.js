// Tiện ích dùng chung cho các Function (không phải route vì tên bắt đầu bằng _)
export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders },
  });
}
export function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function bufToB64(buf) {
  let s = ""; const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function b64ToBuf(b64) {
  const s = atob(b64); const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
}
export async function hashPassword(password, saltB64) {
  const enc = new TextEncoder();
  const salt = saltB64 ? b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return { salt: bufToB64(salt), hash: bufToB64(bits) };
}
export async function verifyPassword(password, saltB64, hashB64) {
  const { hash } = await hashPassword(password, saltB64);
  // so sánh hằng thời gian
  if (hash.length !== hashB64.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ hashB64.charCodeAt(i);
  return diff === 0;
}
export function newToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return bufToB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function sessionCookie(token, expMs) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Expires=${new Date(expMs).toUTCString()}`;
}
export function clearCookie() {
  return "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}
export async function getUser(request, env) {
  const t = getCookie(request, "session");
  if (!t) return null;
  const row = await env.DB.prepare(
    "SELECT s.expires_at AS exp, u.id AS id, u.username AS username, u.is_admin AS is_admin " +
    "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?"
  ).bind(t).first();
  if (!row) return null;
  if (Number(row.exp) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
    return null;
  }
  return { id: row.id, username: row.username, is_admin: !!row.is_admin };
}

// Tự tạo bảng nếu D1 chưa có (an toàn khi quên chạy schema.sql).
// Nhờ vậy trang tạo admin luôn hiện ra, không bao giờ kẹt vì thiếu bảng.
let _schemaReady = false;
export async function ensureSchema(env) {
  if (_schemaReady) return;
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);"
  );
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);"
  );
  // Nhật ký dùng AI (Lớp 2) để admin theo dõi
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS ai_usage(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, ts TEXT NOT NULL, cau_hoi TEXT, model TEXT, ok INTEGER, ghi_chu TEXT);"
  );
  // Cột phân biệt Lớp 1 (không AI) / Lớp 2 (AI) trong cùng bảng nhật ký hỏi đáp
  try { await env.DB.exec("ALTER TABLE ai_usage ADD COLUMN layer TEXT NOT NULL DEFAULT 'L2';"); } catch (e) {}
  // Nhật ký truy cập (đăng nhập): ngày giờ, ai, từ đâu — phục vụ theo dõi nội bộ của admin
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS access_log(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, ts TEXT NOT NULL, ip TEXT, ua TEXT);"
  );
  try { await env.DB.exec("CREATE INDEX IF NOT EXISTS idx_ai_usage_ts ON ai_usage(ts);"); } catch (e) {}
  try { await env.DB.exec("CREATE INDEX IF NOT EXISTS idx_access_log_ts ON access_log(ts);"); } catch (e) {}
  // Quyền dùng Mục hỏi đáp (can_qa) và quyền dùng AI Lớp 2 (can_ai). Thêm cột nếu chưa có.
  for (const col of ["can_qa", "can_ai"]) {
    try { await env.DB.exec("ALTER TABLE users ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0;"); } catch (e) {}
  }
  // Chặn dò mật khẩu (brute-force): đếm số lần đăng nhập sai liên tiếp theo username.
  // locked=1 nghĩa là khóa cứng, chỉ admin mở được — không tự hết hạn theo thời gian.
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS login_attempts(username TEXT PRIMARY KEY, fail_count INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0, locked_at TEXT, last_attempt TEXT NOT NULL);"
  );
  // Bảng ghi lại lỗi ghi log (nếu có) để admin tự chẩn đoán — không ảnh hưởng chức năng chính,
  // chỉ phục vụ debug khi access_log/ai_usage bị thiếu dòng một cách khó hiểu.
  await env.DB.exec(
    "CREATE TABLE IF NOT EXISTS debug_errors(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, noi_dung TEXT, chi_tiet TEXT);"
  );
  _schemaReady = true;
}

// Lấy quyền hiệu lực của một user. Admin mặc định có đủ cả hai quyền.
export async function getPerms(env, userId) {
  await ensureSchema(env);
  const r = await env.DB.prepare("SELECT can_qa, can_ai, is_admin FROM users WHERE id = ?").bind(userId).first();
  const adm = !!(r && r.is_admin);
  // Admin mặc định đủ toàn bộ quyền, không phụ thuộc cột can_qa/can_ai trong DB.
  return { can_qa: adm || !!(r && r.can_qa), can_ai: adm || !!(r && r.can_ai), is_admin: adm };
}

// Ghi 1 dòng nhật ký truy cập (đăng nhập thành công). Không được để lỗi ghi log làm hỏng luồng đăng nhập chính.
export async function logAccess(env, request, userId, username) {
  try {
    await ensureSchema(env);
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "";
    const ua = (request.headers.get("User-Agent") || "").slice(0, 200);
    await env.DB.prepare(
      "INSERT INTO access_log(user_id,username,ts,ip,ua) VALUES(?,?,?,?,?)"
    ).bind(userId, username, new Date().toISOString(), ip, ua).run();
  } catch (e) {
    try {
      await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
        .bind(new Date().toISOString(), "logAccess thất bại cho user_id=" + userId + " username=" + username, String(e && e.message || e)).run();
    } catch (e2) {}
  }
}

// Ghi 1 dòng "lớp 0" vào bảng ai_usage mỗi lần một tài khoản đăng nhập thành công — đại diện cho
// việc "đã truy cập app" ngay cả khi người dùng sau đó không hề đụng vào Mục hỏi đáp. Nhờ vậy Nhật ký
// hệ thống (kind=qa) hiển thị đủ MỌI người dùng đã vào app trong ngày, không chỉ những ai có thao tác
// hỏi đáp thật. Cố tình KHÔNG ghi cau_hoi/model/ok (để NULL) để phân biệt với dòng hỏi đáp thật — cột
// layer='0' là dấu hiệu duy nhất admin.html cần để hiển thị "0" ở cột LỚP và bỏ trống nội dung/KQ.
// Không được để lỗi ghi log này làm hỏng luồng đăng nhập chính — cùng nguyên tắc với logAccess().
export async function logAccessAsQa(env, userId, username) {
  try {
    await ensureSchema(env);
    await env.DB.prepare(
      "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
    ).bind(userId, username, new Date().toISOString(), null, null, null, "", "0").run();
  } catch (e) {
    try {
      await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
        .bind(new Date().toISOString(), "logAccessAsQa thất bại cho user_id=" + userId + " username=" + username, String(e && e.message || e)).run();
    } catch (e2) {}
  }
}

// Dọn log cũ hơn N ngày (mặc định 90) để tránh phình dung lượng D1. Không throw — chỉ best-effort.
export async function purgeOldLogs(env, days = 90) {
  try {
    const cutoff = new Date(Date.now() - days * 24 * 3600 * 1000).toISOString();
    await env.DB.prepare("DELETE FROM ai_usage WHERE ts < ?").bind(cutoff).run();
    await env.DB.prepare("DELETE FROM access_log WHERE ts < ?").bind(cutoff).run();
  } catch (e) {}
}

// ---- Chặn dò mật khẩu (brute-force): khóa CỨNG vĩnh viễn sau 5 lần sai liên tiếp,
// chỉ admin mở lại được — không tự động hết hạn theo thời gian. ----
const LOGIN_MAX_FAILS = 5;

function normUser(username) { return String(username || "").toLowerCase(); }

// Kiểm tra tài khoản này có đang bị khóa cứng không. Trả về true/false.
export async function checkLoginLock(env, username) {
  try {
    await ensureSchema(env);
    const row = await env.DB.prepare("SELECT locked FROM login_attempts WHERE username = ?")
      .bind(normUser(username)).first();
    return !!(row && row.locked);
  } catch (e) { return false; } // lỗi kiểm tra không được phép chặn đăng nhập hợp lệ
}

// Ghi nhận 1 lần đăng nhập sai. Sau LOGIN_MAX_FAILS lần liên tiếp, khóa CỨNG (locked=1) —
// giữ nguyên cho tới khi admin chủ động mở, không tự hết hạn.
export async function recordLoginFailure(env, username) {
  try {
    await ensureSchema(env);
    const key = normUser(username);
    const row = await env.DB.prepare("SELECT fail_count FROM login_attempts WHERE username = ?").bind(key).first();
    const nextCount = (row ? Number(row.fail_count) : 0) + 1;
    const willLock = nextCount >= LOGIN_MAX_FAILS;
    await env.DB.prepare(
      "INSERT INTO login_attempts(username,fail_count,locked,locked_at,last_attempt) VALUES(?,?,?,?,?) " +
      "ON CONFLICT(username) DO UPDATE SET fail_count=excluded.fail_count, " +
      "locked=CASE WHEN login_attempts.locked=1 THEN 1 ELSE excluded.locked END, " +
      "locked_at=CASE WHEN login_attempts.locked=1 THEN login_attempts.locked_at ELSE excluded.locked_at END, " +
      "last_attempt=excluded.last_attempt"
    ).bind(key, nextCount, willLock ? 1 : 0, willLock ? new Date().toISOString() : null, new Date().toISOString()).run();
  } catch (e) {}
}

// Xóa bộ đếm khi đăng nhập đúng — CHỈ áp dụng khi tài khoản chưa bị khóa cứng
// (nếu đã khóa cứng, đăng nhập không thể thành công nữa nên hàm này sẽ không được gọi tới trong trường hợp đó).
export async function clearLoginFailures(env, username) {
  try {
    await ensureSchema(env);
    await env.DB.prepare("DELETE FROM login_attempts WHERE username = ?").bind(normUser(username)).run();
  } catch (e) {}
}

// Danh sách tài khoản đang bị khóa cứng, để admin xem và mở lại.
export async function listLockedUsers(env) {
  try {
    await ensureSchema(env);
    const rs = await env.DB.prepare(
      "SELECT username, fail_count, locked_at FROM login_attempts WHERE locked = 1 ORDER BY locked_at DESC"
    ).all();
    return rs.results || [];
  } catch (e) { return []; }
}

// Admin mở khóa cho 1 tài khoản — xóa hẳn bản ghi để lần đăng nhập tiếp theo tính lại từ đầu.
export async function adminUnlockUser(env, username) {
  await ensureSchema(env);
  await env.DB.prepare("DELETE FROM login_attempts WHERE username = ?").bind(normUser(username)).run();
}
