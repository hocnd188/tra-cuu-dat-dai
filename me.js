import { json, getUser } from "../_utils.js";
export async function onRequestGet({ request, env }) {
  const u = await getUser(request, env);
  if (!u) return json({ error: "unauthorized" }, 401);
  return json(u);
}
