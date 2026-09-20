import { getUser, json, ensureSchema } from "./_utils.js";

async function logVisit(request, env, user) {
  try {
    await ensureSchema(env);
    const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    const recent = await env.DB.prepare(
      "SELECT id FROM ai_usage WHERE user_id = ? AND layer = '0' AND ts > ? ORDER BY id DESC LIMIT 1"
    ).bind(user.id, cutoff).first();
    if (!recent) {
      await env.DB.prepare(
        "INSERT INTO ai_usage(user_id,username,ts,cau_hoi,model,ok,ghi_chu,layer) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(user.id, user.username, new Date().toISOString(), null, null, null, "", "0").run();
    }
  } catch (e) {
    try {
      await env.DB.prepare("INSERT INTO debug_errors(ts,noi_dung,chi_tiet) VALUES(?,?,?)")
        .bind(new Date().toISOString(), "middleware logVisit thất bại cho user_id=" + user.id, String(e && e.message || e)).run();
    } catch (e2) {}
  }
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const p = new URL(request.url).pathname;
  const gated = (p === "/" || p === "/index.html" || p === "/admin.html");
  if (!gated) return next();
  let user = null;
  try { user = await getUser(request, env); } catch (e) { user = null; }
  if (!user) return Response.redirect(new URL("/login.html", request.url).toString(), 302);
  if (p === "/admin.html" && !user.is_admin) return Response.redirect(new URL("/", request.url).toString(), 302);
  if (p === "/" || p === "/index.html") {
    await logVisit(request, env, user);
  }
  return next();
}
