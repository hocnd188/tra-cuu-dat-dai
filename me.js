import { json, getUser, getPerms, logAccessOnce, ensureSchema } from "../_utils.js";

// Trả về thông tin của người dùng đang đăng nhập (dùng cho thanh trạng thái + việc cấp quyền
// Mục hỏi đáp trong index.html) — ĐỒNG THỜI ghi dấu "đã truy cập app" vào Nhật ký hệ thống (lớp "0").
//
// index.html gọi endpoint này 2 LẦN mỗi khi tải trang (một lần cho thanh trạng thái đăng nhập ở cuối
// trang, một lần cho việc bật/tắt Mục hỏi đáp theo quyền), nên đây là điểm DUY NHẤT chắc chắn chạy mỗi
// khi ai đó mở app — kể cả khi họ dùng session cookie có sẵn từ trước (không gọi lại /api/login) và kể
// cả khi họ chỉ dùng tab Tra cứu văn bản, không đụng đến Mục hỏi đáp.
//
// QUAN TRỌNG: việc ghi log được AWAIT ĐỒNG BỘ ngay trong luồng xử lý chính của request này, TRƯỚC khi
// trả response — không dùng waitUntil, không "chạy nền không chờ". Hai cách tiếp cận trước đã thử
// (endpoint /api/ping riêng, và ghi "chạy nền" bên trong getUser()) đều có rủi ro promise bị Cloudflare
// Workers runtime hủy giữa chừng trước khi kịp ghi vào D1 — đúng cơ chế mất log đã từng gặp và sửa ở
// login.js/hoidap.js bằng cách await đồng bộ. Áp dụng đúng bài học đó tại đây.
export async function onRequestGet({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u) return json({}, 200); // chưa đăng nhập — trả object rỗng, index.html xử lý an toàn (mọi field đều undefined/false)

  // Ghi log TRƯỚC khi trả response, đồng bộ hoàn toàn — đảm bảo chắc chắn ghi được.
  await logAccessOnce(env, u.id, u.username);

  const p = await getPerms(env, u.id);
  return json({
    username: u.username,
    is_admin: u.is_admin,
    can_qa: p.can_qa,
    can_ai: p.can_ai,
  }, 200);
}
