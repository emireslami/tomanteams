# Toman Teams

Corporate Services Business Line dashboard.

- Main route: `/main/`
- Register route: `/register`
- Login route: `/login`
- Admin route: `/admin`

## Email Registration Flow

The dashboard is protected by Cloudflare Pages Functions.
Users register with email and password, then wait for admin approval.
Passwords are stored in KV as salted SHA-256 hashes, not plain text.

Flow:

1. User opens `/register`.
2. User enters first name, last name, email, and password.
3. A pending access request is stored in KV.
4. Admin opens `/admin`.
5. Admin approves, rejects, revokes, or updates access through ORBAC.
6. Approved users can log in from `/login`.

OTP by email can be added later before or after password verification.

## ORBAC Model

- User: registered email address
- Role: `viewer`, `manager`, `admin`
- Organization context: Corporate Services, GTM Squads, Product Squads, Customers Operations, Products Operations
- Scope: `dashboard`, `customers`, `product-squads`, `communication`, `admin`
- Permissions: derived from role and stored with the approved access record

## Cloudflare Setup

Configure this Cloudflare Pages environment variable:

- `ADMIN_EMAILS=a.eslami@toman.ir`

Create a Cloudflare KV namespace and bind it to the Pages project as:

- `ACCESS_KV`

Setup checklist:

1. In Cloudflare Pages, create or select the `tomanteams` Pages project.
2. Create a KV namespace for users, requests, approvals, and sessions.
3. Bind that namespace to the Pages project with the variable name `ACCESS_KV`.
4. Add `ADMIN_EMAILS=a.eslami@toman.ir` as a Pages environment variable.
5. Redeploy the Pages project.

You can set the admin email from your Mac with:

```bash
export ADMIN_EMAILS="a.eslami@toman.ir"
./scripts/setup-cloudflare-auth.sh
```

The script still expects the `ACCESS_KV` namespace binding to be created in
Cloudflare Pages settings.
