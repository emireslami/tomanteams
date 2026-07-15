#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="${PROJECT_NAME:-tomanteams}"
ADMIN_EMAILS="${ADMIN_EMAILS:-a.eslami@toman.ir}"

if ! command -v wrangler >/dev/null 2>&1; then
  echo "Wrangler is not installed."
  echo "Install it with: npm install -g wrangler"
  exit 1
fi

echo "Checking Cloudflare login..."
wrangler whoami

cat <<INFO

Make sure a KV namespace exists and is bound to the Pages project:

  Binding name: ACCESS_KV
  Project:      ${PROJECT_NAME}

If it is not created yet, create it from Cloudflare Dashboard:
Workers & Pages -> KV -> Create namespace

Then bind it:
Workers & Pages -> ${PROJECT_NAME} -> Settings -> Functions -> KV namespace bindings

INFO

echo "Setting Cloudflare Pages admin email..."
printf "%s" "${ADMIN_EMAILS}" | wrangler pages secret put ADMIN_EMAILS --project-name "${PROJECT_NAME}"

cat <<INFO

Admin email is set.

Now redeploy Pages from Cloudflare Dashboard or run your normal deployment.

After deploy:
  Register: https://tomanteams.vibebuilders.ir/register
  Login:    https://tomanteams.vibebuilders.ir/login
  Admin:    https://tomanteams.vibebuilders.ir/admin

INFO
