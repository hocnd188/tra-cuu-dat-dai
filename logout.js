import { json, getCookie, clearCookie } from "../_utils.js";
export async function onRequestPost({ request, env }) {
  const t = getCookie(request, "session");
  if (t) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
  return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
}
