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
  // Quyền dùng Mục hỏi đáp (can_qa) và quyền dùng AI Lớp 2 (can_ai). Thêm cột nếu chưa có.
  for (const col of ["can_qa", "can_ai"]) {
    try { await env.DB.exec("ALTER TABLE users ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0;"); } catch (e) {}
  }
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
