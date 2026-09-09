import { getUser, json } from "./_utils.js";
// Cổng bảo vệ: mọi request đều qua đây. Chỉ cho public: trang login + API login/logout/setup.
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const p = url.pathname;
  const isPublic =
    p === "/login.html" ||
    p === "/api/login" ||
    p === "/api/logout" ||
    p === "/api/setup" ||
    p === "/favicon.ico";
  if (isPublic) return next();

  const user = await getUser(request, env);
  if (!user) {
    if (p.startsWith("/api/")) return json({ error: "unauthorized" }, 401);
    return Response.redirect(new URL("/login.html", request.url).toString(), 302);
  }
  // Chỉ admin: trang quản trị + API user
  if ((p === "/admin.html" || p.startsWith("/api/users")) && !user.is_admin) {
    if (p.startsWith("/api/")) return json({ error: "forbidden" }, 403);
    return Response.redirect(new URL("/", request.url).toString(), 302);
  }
  return next();
}
