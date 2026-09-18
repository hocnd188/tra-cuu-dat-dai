import { json, getUser, logAccessAsQa, ensureSchema } from "../_utils.js";

// Ghi dấu "đã truy cập app" mỗi lần index.html được tải — CHẠY MỖI LẦN MỞ TRANG, không chỉ khi
// đăng nhập lần đầu. Đây là điểm khác biệt quan trọng so với việc ghi trong login.js: một khi đã
// đăng nhập, session cookie có hạn 7 ngày, nên những lần mở lại app sau đó KHÔNG gọi lại /api/login —
// nếu chỉ ghi ở login.js thì user dùng session cũ (như DVH trong ảnh chụp bạn gửi) sẽ không để lại
// dấu vết gì trong Nhật ký hệ thống dù họ có thực sự mở app hôm đó. Endpoint riêng biệt này được
// index.html gọi thêm một lần khi tải trang (song song với /api/me hiện có, không thay thế hay sửa
// đổi /api/me), nên bắt được MỌI lần mở app bất kể phiên đăng nhập cũ hay mới.
//
// Không trả về thông tin người dùng nào — chỉ ghi log và báo "đã ghi nhận" (ok:true) hoặc "chưa đăng
// nhập" (ok:false), để không lặp lại bất kỳ logic nào của /api/me mà Claude chưa từng được xem qua.
export async function onRequestGet({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u) return json({ ok: false }, 200); // chưa đăng nhập (hoặc phiên hết hạn) — không có gì để ghi, không phải lỗi

  // Chống ghi trùng nhiều lần trong cùng một lượt mở trang: index.html có thể gọi endpoint này
  // nhiều hơn 1 lần trong một số tình huống trình duyệt (ví dụ tải lại tài nguyên, StrictMode-like
  // behavior của một số trình duyệt/extension). Giới hạn: chỉ ghi nếu CHƯA có dòng "lớp 0" nào của
  // đúng user này trong vòng 60 giây gần nhất — đủ ngắn để không gộp hai lượt mở app thật sự cách
  // nhau vài phút, đủ dài để lọc trùng lặp do gọi lại tức thời.
  try {
    const recent = await env.DB.prepare(
      "SELECT id FROM ai_usage WHERE user_id = ? AND layer = '0' AND ts > ? ORDER BY id DESC LIMIT 1"
    ).bind(u.id, new Date(Date.now() - 60 * 1000).toISOString()).first();
    if (recent) return json({ ok: true, skipped: true }, 200);
  } catch (e) {
    // Nếu việc kiểm tra trùng lặp lỗi vì lý do gì đó, vẫn tiếp tục ghi bình thường — thà ghi dư một
    // dòng còn hơn bỏ sót lượt truy cập thật vì một lỗi không liên quan.
  }

  await logAccessAsQa(env, u.id, u.username);
  return json({ ok: true }, 200);
}
