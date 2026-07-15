#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="${PROJECT_NAME:-tomanteams}"
ADMIN_EMAILS="${ADMIN_EMAILS:-a.eslami@toman.ir}"

if [[ -z "${GOOGLE_CLIENT_ID:-}" ]]; then
  echo "Missing GOOGLE_CLIENT_ID"
  echo "Run: export GOOGLE_CLIENT_ID='your-google-oauth-client-id'"
  exit 1
fi

if [[ -z "${GOOGLE_CLIENT_SECRET:-}" ]]; then
  echo "Missing GOOGLE_CLIENT_SECRET"
  echo "Run: export GOOGLE_CLIENT_SECRET='your-google-oauth-client-secret'"
  exit 1
fi

if ! command -v wrangler >/dev/null 2>&1; then
  echo "Wrangler is not installed."
  echo "Install it with: npm install -g wrangler"
  exit 1
fi

echo "Checking Cloudflare login..."
wrangler whoami

cat <<INFO

Next, make sure a KV namespace exists and is bound to the Pages project:

  Binding name: ACCESS_KV
  Project:      ${PROJECT_NAME}

If it is not created yet, create it from Cloudflare Dashboard:
Workers & Pages -> KV -> Create namespace

Then bind it:
Workers & Pages -> ${PROJECT_NAME} -> Settings -> Functions -> KV namespace bindings

INFO

echo "Setting Cloudflare Pages secrets..."
printf "%s" "${GOOGLE_CLIENT_ID}" | wrangler pages secret put GOOGLE_CLIENT_ID --project-name "${PROJECT_NAME}"
printf "%s" "${GOOGLE_CLIENT_SECRET}" | wrangler pages secret put GOOGLE_CLIENT_SECRET --project-name "${PROJECT_NAME}"
printf "%s" "${ADMIN_EMAILS}" | wrangler pages secret put ADMIN_EMAILS --project-name "${PROJECT_NAME}"

cat <<INFO

Secrets are set.

Now redeploy Pages from Cloudflare Dashboard or run your normal deployment.

Google OAuth redirect URI must include:
  https://tomanteams.vibebuilders.ir/auth/callback

After deploy:
  Login:  https://tomanteams.vibebuilders.ir/login
  Admin:  https://tomanteams.vibebuilders.ir/admin

INFO
