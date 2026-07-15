const SESSION_COOKIE = "tt_session";
const STATE_COOKIE = "tt_oauth_state";
const NEXT_COOKIE = "tt_next";
const SESSION_TTL = 60 * 60 * 24 * 14;

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/login") return renderLogin(request, env);
  if (path === "/auth/google") return startGoogleLogin(request, env);
  if (path === "/auth/callback") return handleGoogleCallback(request, env);
  if (path === "/logout") return logout();

  if (!isConfigured(env)) return renderSetup(request);

  const session = await getSession(request, env);

  if (path === "/admin" || path.startsWith("/admin/")) {
    if (!session) return redirect(`/login?next=${encodeURIComponent(path)}`);
    if (!isAdmin(session.email, env)) return htmlPage("Access denied", `<p>Your account is not allowed to manage access requests.</p><p><a class="button" href="/main/">Back to dashboard</a></p>`, 403);
    if (request.method === "POST") return handleAdminAction(request, env);
    return renderAdmin(env, session);
  }

  if (session && (await isApproved(session.email, env))) return context.next();
  return redirect(`/login?next=${encodeURIComponent(path + url.search + url.hash)}`);
}

function isConfigured(env) {
  return env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.ACCESS_KV && env.SESSION_SECRET;
}

function adminEmails(env) {
  return String(env.ADMIN_EMAILS || "").split(",").map((email) => email.trim().toLowerCase()).filter(Boolean);
}

function isAdmin(email, env) {
  return adminEmails(env).includes(String(email || "").toLowerCase());
}

async function isApproved(email, env) {
  const normalized = String(email || "").toLowerCase();
  if (isAdmin(normalized, env)) return true;
  return Boolean(await env.ACCESS_KV.get(`approved:${normalized}`));
}

async function getSession(request, env) {
  const id = getCookie(request, SESSION_COOKIE);
  if (!id) return null;
  const value = await env.ACCESS_KV.get(`session:${id}`, "json");
  if (!value?.email) return null;
  return value;
}

async function startGoogleLogin(request, env) {
  if (!isConfigured(env)) return renderSetup(request);
  const url = new URL(request.url);
  const state = crypto.randomUUID();
  const next = safeNext(url.searchParams.get("next") || "/main/");
  const redirectUri = `${url.origin}/auth/callback`;
  const google = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  google.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  google.searchParams.set("redirect_uri", redirectUri);
  google.searchParams.set("response_type", "code");
  google.searchParams.set("scope", "openid email profile");
  google.searchParams.set("state", state);
  google.searchParams.set("prompt", "select_account");
  return redirect(google.toString(), [
    cookie(STATE_COOKIE, state, { maxAge: 600 }),
    cookie(NEXT_COOKIE, next, { maxAge: 600 }),
  ]);
}

async function handleGoogleCallback(request, env) {
  if (!isConfigured(env)) return renderSetup(request);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || state !== getCookie(request, STATE_COOKIE)) {
    return htmlPage("Login failed", "<p>The Google login response could not be verified.</p><p><a class=\"button\" href=\"/login\">Try again</a></p>", 400);
  }

  const redirectUri = `${url.origin}/auth/callback`;
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenResponse.ok) return htmlPage("Login failed", "<p>Google did not accept the login response.</p><p><a class=\"button\" href=\"/login\">Try again</a></p>", 400);

  const token = await tokenResponse.json();
  const userResponse = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { authorization: `Bearer ${token.access_token}` },
  });
  if (!userResponse.ok) return htmlPage("Login failed", "<p>Could not read your Google account profile.</p><p><a class=\"button\" href=\"/login\">Try again</a></p>", 400);

  const profile = await userResponse.json();
  const email = String(profile.email || "").toLowerCase();
  if (!email || !profile.email_verified) return htmlPage("Login failed", "<p>Your Google email address is not verified.</p>", 403);

  const rejected = await env.ACCESS_KV.get(`rejected:${email}`);
  if (rejected && !isAdmin(email, env)) return htmlPage("Access rejected", "<p>Your access request was rejected by an administrator.</p>", 403);

  if (await isApproved(email, env)) {
    const sessionId = crypto.randomUUID();
    await env.ACCESS_KV.put(`session:${sessionId}`, JSON.stringify({
      email,
      name: profile.name || email,
      picture: profile.picture || "",
      createdAt: new Date().toISOString(),
    }), { expirationTtl: SESSION_TTL });
    return redirect(safeNext(getCookie(request, NEXT_COOKIE) || "/main/"), [
      cookie(SESSION_COOKIE, sessionId, { maxAge: SESSION_TTL }),
      cookie(STATE_COOKIE, "", { maxAge: 0 }),
      cookie(NEXT_COOKIE, "", { maxAge: 0 }),
    ]);
  }

  await env.ACCESS_KV.put(`pending:${email}`, JSON.stringify({
    email,
    name: profile.name || email,
    picture: profile.picture || "",
    requestedAt: new Date().toISOString(),
  }));
  return htmlPage("Access requested", `<p>Your Google account <strong>${escapeHtml(email)}</strong> has requested access.</p><p>An administrator can approve or reject it from <code>/admin</code>.</p><p><a class="button" href="/login">Use another account</a></p>`, 202);
}

async function handleAdminAction(request, env) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const email = String(form.get("email") || "").trim().toLowerCase();
  if (!email) return redirect("/admin");
  if (action === "approve") {
    const pending = await env.ACCESS_KV.get(`pending:${email}`, "json");
    await env.ACCESS_KV.put(`approved:${email}`, JSON.stringify({
      email,
      name: pending?.name || email,
      approvedAt: new Date().toISOString(),
    }));
    await env.ACCESS_KV.delete(`pending:${email}`);
    await env.ACCESS_KV.delete(`rejected:${email}`);
  }
  if (action === "reject") {
    await env.ACCESS_KV.put(`rejected:${email}`, JSON.stringify({ email, rejectedAt: new Date().toISOString() }));
    await env.ACCESS_KV.delete(`pending:${email}`);
    await env.ACCESS_KV.delete(`approved:${email}`);
  }
  if (action === "revoke") {
    await env.ACCESS_KV.delete(`approved:${email}`);
    await env.ACCESS_KV.put(`rejected:${email}`, JSON.stringify({ email, rejectedAt: new Date().toISOString() }));
  }
  return redirect("/admin");
}

async function renderAdmin(env, session) {
  const pending = await readList(env, "pending:");
  const approved = await readList(env, "approved:");
  const pendingRows = pending.length ? pending.map((item) => requestRow(item, ["approve", "reject"])).join("") : "<tr><td colspan=\"4\">No pending requests</td></tr>";
  const approvedRows = approved.length ? approved.map((item) => requestRow(item, ["revoke"])).join("") : "<tr><td colspan=\"4\">No approved users</td></tr>";
  return htmlPage("Access Admin", `
    <p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>
    <p><a class="button" href="/main/">Dashboard</a> <a class="button secondary" href="/logout">Logout</a></p>
    <h2>Pending Requests</h2>
    <table><thead><tr><th>Email</th><th>Name</th><th>Date</th><th>Action</th></tr></thead><tbody>${pendingRows}</tbody></table>
    <h2>Approved Users</h2>
    <table><thead><tr><th>Email</th><th>Name</th><th>Date</th><th>Action</th></tr></thead><tbody>${approvedRows}</tbody></table>
  `);
}

function requestRow(item, actions) {
  const date = item.requestedAt || item.approvedAt || "";
  const buttons = actions.map((action) => `<form method="post" style="display:inline"><input type="hidden" name="email" value="${escapeHtml(item.email)}"><button name="action" value="${action}">${action}</button></form>`).join(" ");
  return `<tr><td>${escapeHtml(item.email)}</td><td>${escapeHtml(item.name || "")}</td><td>${escapeHtml(date)}</td><td>${buttons}</td></tr>`;
}

async function readList(env, prefix) {
  const listed = await env.ACCESS_KV.list({ prefix });
  const rows = await Promise.all(listed.keys.map((key) => env.ACCESS_KV.get(key.name, "json")));
  return rows.filter(Boolean).sort((a, b) => String(b.requestedAt || b.approvedAt || "").localeCompare(String(a.requestedAt || a.approvedAt || "")));
}

function renderLogin(request, env) {
  if (!isConfigured(env)) return renderSetup(request);
  const url = new URL(request.url);
  const next = safeNext(url.searchParams.get("next") || "/main/");
  return htmlPage("Sign in", `
    <p>Use your Google account to access the Corporate Services dashboard.</p>
    <p>First-time users will request access and wait for admin approval.</p>
    <p><a class="button" href="/auth/google?next=${encodeURIComponent(next)}">Continue with Google</a></p>
  `);
}

function renderSetup(request) {
  return htmlPage("Authentication setup required", `
    <p>Google login is enabled in code, but Cloudflare environment variables and KV are not configured yet.</p>
    <ul>
      <li><code>GOOGLE_CLIENT_ID</code></li>
      <li><code>GOOGLE_CLIENT_SECRET</code></li>
      <li><code>SESSION_SECRET</code></li>
      <li><code>ADMIN_EMAILS</code></li>
      <li><code>ACCESS_KV</code> KV binding</li>
    </ul>
  `, 500);
}

function logout() {
  return redirect("/login", [cookie(SESSION_COOKIE, "", { maxAge: 0 })]);
}

function safeNext(value) {
  const next = String(value || "/main/");
  if (!next.startsWith("/") || next.startsWith("//")) return "/main/";
  if (next.startsWith("/auth/") || next.startsWith("/login")) return "/main/";
  return next;
}

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  return header.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1) || "";
}

function cookie(name, value, options = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  return parts.join("; ");
}

function redirect(location, cookies = []) {
  const headers = new Headers({ location });
  cookies.forEach((value) => headers.append("set-cookie", value));
  return new Response(null, { status: 302, headers });
}

function htmlPage(title, body, status = 200) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>
    body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fa;color:#172033;line-height:1.45}
    main{width:min(920px,calc(100% - 40px));margin:56px auto;padding:24px;border:1px solid #dce3ec;border-radius:8px;background:#fff;box-shadow:0 16px 40px rgba(28,43,68,.08)}
    h1{margin:0 0 12px;font-size:32px;line-height:1.1}h2{margin:28px 0 12px;font-size:20px}p{color:#5f6b7c}.button,button{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:9px 13px;border:1px solid #bfd0f7;border-radius:8px;background:#eaf2ff;color:#2f67d8;font:inherit;font-size:13px;font-weight:800;text-decoration:none;cursor:pointer}.button.secondary{border-color:#dce3ec;background:#fff;color:#34425a}
    table{width:100%;border:1px solid #dce3ec;border-collapse:separate;border-spacing:0;border-radius:8px;overflow:hidden}th,td{padding:12px;border-right:1px solid #dce3ec;border-bottom:1px solid #dce3ec;text-align:left;font-size:13px}th{background:#eef3f8}td:last-child,th:last-child{border-right:0}tr:last-child td{border-bottom:0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  </style></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}
