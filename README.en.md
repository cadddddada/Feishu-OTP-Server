# Feishu OTP Server

An One-Time Password (OTP) service implementation for Feishu enterprise applications, running on EdgeOne Makers: **all Feishu business logic runs in an Edge Function**, and a Cloud Function acts only as an expiry timer.

## Architecture and Flow

```
Feishu event ──► Edge Function /api/feishu_callback
                  │
                  ├─ Validation: URL verification / Token / Signature / AES decrypt / timeliness
                  ├─ Handle message: get OTP (KV read + TOTP), private-chat add/update key
                  ├─ Send text / OTP card / management notification (fetch to Feishu; token stays in Edge)
                  │
                  ├─ After sending the card: HMAC-signed handoff to Cloud /api/expiry (schedule_expiry with absolute timestamps)
                  └─ Return 200 to Feishu

Cloud Function /api/expiry (timer role only)
                  ├─ After signature verification, only records {message_id, renew_at, expire_at, user_id, key_name} and returns 200
                  └─ Two background timers fire on absolute timestamps and send HMAC-signed commands to Edge /api/expire:
                     renew_at -> renew_otp (push a renewed key); expire_at -> expire_message (mark expired)

Edge Function /api/expire
                  ├─ renew_otp: regenerate the OTP and PATCH the user card (new key, still valid)
                  └─ expire_message: PATCH the card to "expired"
```

## Key Features

- **OTP Generation and Query**: Send "xxxOTP / xxx验证码 / xxx密钥 / xxx动态码" to get a dynamic code, e.g. "阿里云OTP"
- **Self-service key management**: Send "添加密钥 XXX <secret>" in a private chat to add/update a key in KV
- **No key caching**: Every OTP generation reads KV in real time on the Edge side (binding variable `KV_NAMESPACE`, namespace `TOTP_SERVER`)
- **Card renewal and expiry update**: When the first key expires, the Cloud timer triggers Edge to push a renewed key; when it expires again, the card is marked "expired"
- **Merged management notification**: One request pushes 2 OTPs in total (including the renewal), and the management group card merges them into one (request time / final expiry time / push count)
- **tenant_access_token never travels over APIs**: the token is only fetched, cached and used inside Edge; internal payloads never contain it
- **Signed internal communication**: Edge ↔ Cloud commands are signed with `EDGE_SYNC_SECRET` + HMAC-SHA256 over a canonical JSON payload, valid for 60 seconds (`createdAt`)

## Project Structure

```
feishu-otp-server/
├── .env                         # Environment variables configuration
├── package.json                 # Node.js project config (dependency: pinyin-pro)
├── edge-functions/
│   ├── api/_shared.js           # Shared utilities: signing / KV / token / base resolution / expired card (no route)
│   ├── api/feishu_callback.js   # Edge callback entry (route /api/feishu_callback)
│   └── api/expire.js            # Edge receives Cloud expire command and PATCHes Feishu (route /api/expire)
├── cloud-functions/
│   └── api/expiry.js            # Cloud timer: record + signed expire command to Edge (route /api/expiry)
└── tests/
    ├── edge_feishu_callback.test.mjs
    ├── edge_expire.test.mjs
    └── cloud_expiry.test.mjs
```

## Core Module Description

### edge-functions/api/_shared.js (shared utilities)

- Signing: `canonicalJson` (recursively sorted keys), `signPayload` / `verifyPayload` (HMAC-SHA256, 60 s freshness)
- Base resolution: `resolveBase` (`EDGE_FUNCTION_BASE` / `CLOUD_FUNCTION_BASE` first, otherwise request same-origin)
- KV read/write and `getTenantAccessToken` (KV-cached, Edge-internal only)
- `buildExpiredCard` / `expireFeishuCard` (Edge PATCHes Feishu to mark a card expired)
- Unified `json()` responses: `{code:0,data}` / `{code:1,message}`, with `X-Edge-Error*` headers on errors

### edge-functions/api/feishu_callback.js (Edge Function)

- Feishu callback protocol: URL verification, Token/signature verification, AES decryption, timeliness check
- OTP query, private-chat key add, text/card/management notifications
- After sending the OTP card, POSTs a signed `{command:'schedule_expiry', message_id, renew_at, expire_at, user_id, key_name, createdAt}` to Cloud `/api/expiry` (absolute timestamps avoid network-delay accumulation)
- The management notification is merged: request time = the request moment, expiry time = the final expiry after renewal, push count = 2
- Built-in timing logs: `[TIMING]` prints the elapsed time of validation, OTP generation, card send, handoff and management notification stages

### cloud-functions/api/expiry.js (Cloud Function, timer role only)

- After verifying the signature (`EDGE_SYNC_SECRET`), only records the delayed update data (`renew_at` / `expire_at` absolute timestamps) and returns 200 immediately
- Two background timers fire on the timestamps and send signed commands to Edge `/api/expire`: `renew_otp` (renewal) and `expire_message` (expiry)
- Never fetches, holds, or transmits tenant_access_token

### edge-functions/api/expire.js (Edge Function)

- After verifying the signature (`EDGE_SYNC_SECRET`, 60 s freshness), calls Feishu `PATCH /im/v1/messages/{id}`:
  - `renew_otp`: regenerates the current-window OTP and updates the card (still valid)
  - `expire_message`: marks the card as "expired"

## Installation and Configuration

### Requirements

- Node.js 18+ (local development)
- Feishu open platform account and application
- EdgeOne Makers (EdgeOne CLI: `npm install -g edgeone`)

### Environment Variables

```env
APP_ID=your_app_id
APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
# Domain used by the Cloud Function to call the Edge Function (optional, defaults to request same-origin)
EDGE_FUNCTION_BASE=
# Domain used by the Edge Function to forward to the Cloud Function (optional, defaults to request same-origin)
CLOUD_FUNCTION_BASE=
# Shared signing secret for Edge ↔ Cloud internal communication (HMAC-SHA256, must match on both sides)
EDGE_SYNC_SECRET=your_shared_secret
```

### Deployment Steps

1. Install dependencies: `npm install`
2. Configure the environment variables in EdgeOne Makers and bind the KV namespace (binding variable `KV_NAMESPACE` → namespace `TOTP_SERVER`)
3. Make sure `EDGE_SYNC_SECRET` is set to the same value on both the Edge and Cloud sides
4. Add secrets to KV (or let users add them via the private-chat command): `TOTP_SECRET` (default), `{UPPERCASE_PINYIN}_TOTP_SECRET` (named)
5. After deployment, the Feishu callback URL stays `https://[your-domain]/api/feishu_callback` (served by the Edge Function)
6. Local development: `npm run dev`; push to the remote repository for automatic build and deployment

Note: the `pinyin-pro` dependency in the Edge Function is bundled via npm (beta). On first deployment, verify with a minimal probe function that dependencies build correctly.

### Local Tests

```bash
npm test
```

Covers: Edge callback (GET / URL verification / Token / signature / timeliness / TOTP / pinyin / AES / full OTP flow with signed handoff / key add / group-chat rejection / encrypted events), Edge `/api/expire` (signature verification / stale signature / body validation / PATCH expired card), and Cloud timer (signature verification / record and ack / signed expire command / default same-origin).

## Contact

If you have any questions or suggestions, feel free to provide feedback through the Gitee platform.
