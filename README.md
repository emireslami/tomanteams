# Toman Teams

Corporate Services Business Line dashboard.

- Main route: `/main/`
- Login route: `/login`
- Admin route: `/admin`

## Google Login Setup

The dashboard is protected by Cloudflare Pages Functions and Google OAuth.
First-time Google accounts create an access request. Admins use an ORBAC
access model from `/admin` to approve, reject, revoke, or update users.

ORBAC dimensions:

- User: Google account email
- Role: `viewer`, `manager`, `admin`
- Organization context: Corporate Services, GTM Squads, Product Squads, Customers Operations, Products Operations
- Scope: `dashboard`, `customers`, `product-squads`, `communication`, `admin`
- Permissions: derived from role and stored with the approved access record

Configure these Cloudflare Pages environment variables:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `ADMIN_EMAILS=a.eslami@toman.ir`

Create a Cloudflare KV namespace and bind it to the Pages project as:

- `ACCESS_KV`

Google OAuth redirect URI:

- `https://tomanteams.vibebuilders.ir/auth/callback`
- Add the `pages.dev` callback too if you test on the Pages preview domain.

## Cloudflare Setup Checklist

1. In Google Cloud Console, create an OAuth 2.0 Client ID for a Web Application.
2. Add the authorized redirect URI: `https://tomanteams.vibebuilders.ir/auth/callback`.
3. In Cloudflare Pages, create or select the `tomanteams` Pages project.
4. Create a KV namespace for access requests and approved users.
5. Bind that namespace to the Pages project with the variable name `ACCESS_KV`.
6. Add `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `ADMIN_EMAILS=a.eslami@toman.ir` as Pages environment variables.
7. Redeploy the Pages project.

You can set the Pages secrets from your Mac with:

```bash
export GOOGLE_CLIENT_ID="your-google-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-google-oauth-client-secret"
export ADMIN_EMAILS="a.eslami@toman.ir"
./scripts/setup-cloudflare-auth.sh
```

The script still expects the `ACCESS_KV` namespace binding to be created in
Cloudflare Pages settings.
