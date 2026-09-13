import { json, getUser, ensureSchema } from "../_utils.js";
export async function onRequestGet({ request, env }) {
  await ensureSchema(env);
  const u = await getUser(request, env);
  if (!u || !u.is_admin) return json({ error: "forbidden" }, 403);
  const rs = await env.DB.prepare(
    "SELECT id, username, ts, cau_hoi, model, ok FROM ai_usage ORDER BY id DESC LIMIT 100"
  ).all();
  const today = new Date().toISOString().slice(0, 10);
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM ai_usage WHERE substr(ts,1,10) = ?").bind(today).first();
  return json({ today: (c && c.n) || 0, rows: rs.results || [] });
}
