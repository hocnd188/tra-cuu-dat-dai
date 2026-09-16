import { json, getUser, getPerms, ensureSchema, purgeOldLogs } from "../_utils.js";

const SYS = `Bạn là trợ lý pháp chế về PHÁP LUẬT ĐẤT ĐAI Việt Nam, soạn phần nội dung trả lời cho cơ quan nhà nước.
NGUYÊN TẮC BẮT BUỘC:
1. CHỈ dùng các quy định trong mục "CÁC QUY ĐỊNH ĐƯỢC PHÉP DÙNG". Tuyệt đối không viện dẫn điều khoản, số hiệu hay nội dung ngoài danh sách đó. Không suy đoán, không bịa.
2. Mỗi khẳng định phải gắn căn cứ cụ thể: nêu đúng "Điều … khoản … của <tên văn bản>".
3. Nếu một quy định có ghi TÌNH TRẠNG (đã bị sửa đổi/bổ sung/thay thế/hết hiệu lực) thì PHẢI nêu rõ và áp dụng theo văn bản còn hiệu lực; ghi mốc hiệu lực nếu có.
4. Nếu căn cứ được cung cấp KHÔNG đủ để trả lời, nói rõ "chưa đủ căn cứ trong bộ văn bản" và đề nghị bổ sung/hỏi cơ quan có thẩm quyền — KHÔNG tự kết luận.
5. Văn phong hành chính, trung tính, chính xác.
Hãy viết phần nội dung trả lời (không cần quốc hiệu/tiêu ngữ, hệ thống tự thêm), gồm: nêu tóm tắt nội dung hỏi; "Về vấn đề này, căn cứ quy định pháp luật đất đai hiện hành, … có ý kiến như sau:"; liệt kê từng căn cứ kèm trả lời; cảnh báo hiệu lực nếu có; câu kết đề nghị thực hiện. Kết thúc bằng dòng: "(Bản thảo do hệ thống hỗ trợ soạn — cần chuyên viên rà soát trước khi ban hành.)"`;

export async function onRequestPost({ request, env, waitUntil }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  const p = await getPerms(env, u.id);
  if (!p.can_ai) return json({ error: "Bạn chưa được cấp quyền dùng AI (Lớp 2). Vui lòng liên hệ quản trị viên." }, 403);
  if (!env.AI) return json({ error: "Chưa bật Workers AI (thiếu binding AI trong wrangler.toml)." }, 500);

  const { cau_hoi, cancu } = await request.json().catch(() => ({}));
  if (!cau_hoi || !String(cau_hoi).trim()) return json({ error: "Thiếu nội dung câu hỏi." }, 400);

  const model = env.AI_MODEL || "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
  const ctx = (cancu || []).map(c =>
    `[${c.id}] ${c.vb} — Điều ${c.dieu}${c.khoan ? (" khoản " + c.khoan) : ""}: ${c.text}` +
    (c.amend ? ("  | TÌNH TRẠNG: " + c.amend) : "")
  ).join("\n\n");
  const usr = `NỘI DUNG CẦN GIẢI ĐÁP:\n${cau_hoi}\n\nCÁC QUY ĐỊNH ĐƯỢC PHÉP DÙNG (chỉ dùng trong phạm vi này):\n${ctx || "(không có — hãy trả lời là chưa đủ căn cứ)"}`;

  let out = "", ok = 0, err = "";
  try {
    const r = await env.AI.run(model, {
      messages: [{ role: "system", content: SYS }, { role: "user", content: usr }],
      max_tokens: 2048,
    });
    out = (r && (r.response || (r.result && r.result.response))) || "";
    ok = out ? 1 : 0;
    if (!ok) err = "empty response";
  } catch (e) { err = String(e && e.message || e).slice(0, 200); }

  // Ghi nhật ký để admin theo dõi (kể cả khi lỗi) — chạy nền (waitUntil), không chặn phản hồi cho user
  const logTask = (async () => {
    try {
      await env.DB.prepare(
        "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(u.id, u.username, new Date().toISOString(), String(cau_hoi), model, ok, err, "L2").run();
    } catch (e) {}
  })();
  if (typeof waitUntil === "function") {
    waitUntil(logTask);
    waitUntil(purgeOldLogs(env, 90));
  } else {
    await logTask;
  }

  if (!ok) return json({ error: "AI không phản hồi (" + err + "). Thử lại sau." }, 502);
  return json({ cong_van: out, model });
}
