import { getUser, json } from "./_utils.js";
export async function onRequest(context) {
  const { request, env, next } = context;
  const p = new URL(request.url).pathname;
  const gated = (p === "/" || p === "/index.html" || p === "/admin.html");
  if (!gated) return next();
  let user = null;
  try { user = await getUser(request, env); } catch (e) { user = null; }
  if (!user) return Response.redirect(new URL("/login.html", request.url).toString(), 302);
  if (p === "/admin.html" && !user.is_admin) return Response.redirect(new URL("/", request.url).toString(), 302);
  return next();
}
