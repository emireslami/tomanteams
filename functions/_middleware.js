const SESSION_COOKIE = "tt_session";
const STATE_COOKIE = "tt_oauth_state";
const NEXT_COOKIE = "tt_next";
const SESSION_TTL = 60 * 60 * 24 * 14;
const ORBAC_ROLES = ["viewer", "manager", "admin"];
const ORBAC_ORGS = ["Corporate Services", "GTM Squads", "Product Squads", "Customers Operations", "Products Operations"];
const ORBAC_SCOPES = ["dashboard", "customers", "product-squads", "communication", "admin"];
const ORBAC_PERMISSIONS = {
  viewer: ["view:dashboard"],
  manager: ["view:dashboard", "view:customers", "view:product-squads"],
  admin: ["view:dashboard", "view:customers", "view:product-squads", "manage:access"],
};

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
    if (!(await canManageAccess(session.email, env))) return htmlPage("Access denied", `<p>Your account is not allowed to manage access requests.</p><p><a class="button" href="/main/">Back to dashboard</a></p>`, 403);
    if (request.method === "POST") return handleAdminAction(request, env);
    return renderAdmin(env, session);
  }

  if (session && (await isAuthorized(session.email, path, env))) return context.next();
  return redirect(`/login?next=${encodeURIComponent(path + url.search + url.hash)}`);
}

function isConfigured(env) {
  return env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.ACCESS_KV;
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

async function isAuthorized(email, path, env) {
  const normalized = String(email || "").toLowerCase();
  if (isAdmin(normalized, env)) return true;
  const access = await env.ACCESS_KV.get(`approved:${normalized}`, "json");
  if (!access) return false;
  return normalizeAccess(access).scopes.includes(scopeForPath(path));
}

async function canManageAccess(email, env) {
  const normalized = String(email || "").toLowerCase();
  if (isAdmin(normalized, env)) return true;
  const access = await env.ACCESS_KV.get(`approved:${normalized}`, "json");
  if (!access) return false;
  const normalizedAccess = normalizeAccess(access);
  return normalizedAccess.role === "admin" && normalizedAccess.scopes.includes("admin") && normalizedAccess.permissions.includes("manage:access");
}

function scopeForPath(path) {
  if (path.startsWith("/product-squads")) return "product-squads";
  if (path.startsWith("/main")) return "dashboard";
  return "dashboard";
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
  const access = orbacFromForm(form, action === "approve" ? "viewer" : "viewer");
  if (!email) return redirect("/admin");
  if (action === "approve") {
    const pending = await env.ACCESS_KV.get(`pending:${email}`, "json");
    await env.ACCESS_KV.put(`approved:${email}`, JSON.stringify({
      email,
      name: pending?.name || email,
      ...access,
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
  if (action === "update") {
    const approved = await env.ACCESS_KV.get(`approved:${email}`, "json");
    if (approved) {
      await env.ACCESS_KV.put(`approved:${email}`, JSON.stringify({
        ...approved,
        ...access,
        updatedAt: new Date().toISOString(),
      }));
    }
  }
  return redirect("/admin");
}

async function renderAdmin(env, session) {
  const pending = await readList(env, "pending:");
  const approved = await readList(env, "approved:");
  const pendingRows = pending.length ? pending.map((item) => pendingRequestRow(item)).join("") : "<tr><td colspan=\"6\">No pending requests</td></tr>";
  const approvedRows = approved.length ? approved.map((item) => approvedUserRow(item)).join("") : "<tr><td colspan=\"7\">No approved users</td></tr>";
  return htmlPage("ORBAC Access Admin", `
    <p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>
    <p><a class="button" href="/main/">Dashboard</a> <a class="button secondary" href="/logout">Logout</a></p>
    <div class="note"><strong>ORBAC model:</strong> Admin grants access by user identity, role, organization context, resource scope, and permissions.</div>
    <h2>Pending Requests</h2>
    <table><thead><tr><th>Email</th><th>Name</th><th>Requested</th><th>Role</th><th>Organization / Scope</th><th>Action</th></tr></thead><tbody>${pendingRows}</tbody></table>
    <h2>Approved Users</h2>
    <table><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Organization</th><th>Scope</th><th>Permissions</th><th>Action</th></tr></thead><tbody>${approvedRows}</tbody></table>
  `);
}

function pendingRequestRow(item) {
  return `<tr>
    <td>${escapeHtml(item.email)}</td>
    <td>${escapeHtml(item.name || "")}</td>
    <td>${escapeHtml(item.requestedAt || "")}</td>
    <td><span class="pill">Pending</span></td>
    <td><span class="pill muted">Assigned on approval</span></td>
    <td>
      <form method="post" class="orbac-form">
        <input type="hidden" name="email" value="${escapeHtml(item.email)}">
        ${roleSelect("role", "viewer")}
        ${orgSelect("organization", "Corporate Services")}
        ${scopeSelect("scope", ["dashboard"])}
        <button name="action" value="approve">Approve</button>
        <button name="action" value="reject" class="danger">Reject</button>
      </form>
    </td>
  </tr>`;
}

function approvedUserRow(item) {
  const access = normalizeAccess(item);
  return `<tr>
    <td>${escapeHtml(item.email)}</td>
    <td>${escapeHtml(item.name || "")}</td>
    <td><span class="pill">${escapeHtml(access.role)}</span></td>
    <td>${escapeHtml(access.organization)}</td>
    <td>${access.scopes.map((scope) => `<span class="pill muted">${escapeHtml(scope)}</span>`).join(" ")}</td>
    <td>${access.permissions.map((permission) => `<span class="pill permission">${escapeHtml(permission)}</span>`).join(" ")}</td>
    <td>
      <form method="post" class="orbac-form">
        <input type="hidden" name="email" value="${escapeHtml(item.email)}">
        ${roleSelect("role", access.role)}
        ${orgSelect("organization", access.organization)}
        ${scopeSelect("scope", access.scopes)}
        <button name="action" value="update">Update</button>
        <button name="action" value="revoke" class="danger">Revoke</button>
      </form>
    </td>
  </tr>`;
}

function orbacFromForm(form, fallbackRole) {
  const role = ORBAC_ROLES.includes(String(form.get("role"))) ? String(form.get("role")) : fallbackRole;
  const organization = ORBAC_ORGS.includes(String(form.get("organization"))) ? String(form.get("organization")) : "Corporate Services";
  const scopes = form.getAll("scope").map(String).filter((scope) => ORBAC_SCOPES.includes(scope));
  return {
    role,
    organization,
    scopes: scopes.length ? scopes : ["dashboard"],
    permissions: ORBAC_PERMISSIONS[role] || ORBAC_PERMISSIONS.viewer,
  };
}

function normalizeAccess(item) {
  const role = ORBAC_ROLES.includes(item.role) ? item.role : "viewer";
  return {
    role,
    organization: ORBAC_ORGS.includes(item.organization) ? item.organization : "Corporate Services",
    scopes: Array.isArray(item.scopes) && item.scopes.length ? item.scopes.filter((scope) => ORBAC_SCOPES.includes(scope)) : ["dashboard"],
    permissions: Array.isArray(item.permissions) && item.permissions.length ? item.permissions : ORBAC_PERMISSIONS[role],
  };
}

function roleSelect(name, selected) {
  return `<select name="${name}">${ORBAC_ROLES.map((role) => `<option value="${role}"${role === selected ? " selected" : ""}>${role}</option>`).join("")}</select>`;
}

function orgSelect(name, selected) {
  return `<select name="${name}">${ORBAC_ORGS.map((org) => `<option value="${escapeHtml(org)}"${org === selected ? " selected" : ""}>${escapeHtml(org)}</option>`).join("")}</select>`;
}

function scopeSelect(name, selected) {
  const selectedSet = new Set(selected);
  return `<div class="scope-grid">${ORBAC_SCOPES.map((scope) => `<label><input type="checkbox" name="${name}" value="${scope}"${selectedSet.has(scope) ? " checked" : ""}> ${scope}</label>`).join("")}</div>`;
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
    h1{margin:0 0 12px;font-size:32px;line-height:1.1}h2{margin:28px 0 12px;font-size:20px}p{color:#5f6b7c}.button,button{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:9px 13px;border:1px solid #bfd0f7;border-radius:8px;background:#eaf2ff;color:#2f67d8;font:inherit;font-size:13px;font-weight:800;text-decoration:none;cursor:pointer}.button.secondary{border-color:#dce3ec;background:#fff;color:#34425a}button.danger{border-color:#fecaca;background:#fff1f2;color:#be123c}
    table{width:100%;border:1px solid #dce3ec;border-collapse:separate;border-spacing:0;border-radius:8px;overflow:hidden}th,td{padding:12px;border-right:1px solid #dce3ec;border-bottom:1px solid #dce3ec;text-align:left;font-size:13px}th{background:#eef3f8}td:last-child,th:last-child{border-right:0}tr:last-child td{border-bottom:0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
    select{min-height:34px;padding:7px 9px;border:1px solid #dce3ec;border-radius:8px;background:#fff;font:inherit;font-size:13px}.orbac-form{display:grid;gap:8px;min-width:220px}.scope-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.scope-grid label{display:flex;gap:6px;align-items:center;color:#34425a;font-size:12px}.pill{display:inline-flex;margin:2px;padding:4px 7px;border-radius:999px;background:#eaf2ff;color:#2f67d8;font-size:11px;font-weight:800}.pill.muted{background:#eef3f8;color:#34425a}.pill.permission{background:#e8f7f3;color:#18866f}.note{padding:12px 14px;border:1px solid #d7e7e2;border-radius:8px;background:#e8f7f3;color:#315f56}
  </style></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}
