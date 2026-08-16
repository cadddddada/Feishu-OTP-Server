# Feishu OTP Server

An One-Time Password (OTP) service implementation for Feishu enterprise applications, running on EdgeOne Makers: **all Feishu business logic runs in an Edge Function**, and a Cloud Function acts only as an expiry timer.

## Architecture and Flow

```
Feishu event ──► Edge Function /api/feishu_callback
                  │
                  ├─ Validation: URL verification / Token / Signature / AES decrypt / timeliness
                  ├─ Handle message: get OTP (KV read + TOTP), private-chat add/update key
                   ├─ Send text / OTP card / management notification (fetch to Feishu)
                   ├─ Pre-generate the next-window renewal code (codeB) and obtain the Feishu auth token (with expiry)
                   │
                   ├─ After sending the card: AES-256-GCM encrypted + HMAC-signed handoff to Cloud /api/expiry (template code + fill data + target time, carrying codeB and the token)
                   └─ Return 200 to Feishu

Cloud Function /api/expiry (scheduled HTTP sender, direct to Feishu)
                   ├─ After signature verification, only records scheduled tasks (template / data / targetAt) and returns 200
                   └─ When the absolute timestamps fire, directly PATCHes Feishu from pre-encoded Cloud templates:
                      renew_otp -> update to the renewal code (still valid); expire_message -> mark expired
                      (refreshes the token from env credentials when it is missing or about to expire)
```

## Key Features

- **OTP Generation and Query**: Send "xxxOTP / xxx验证码 / xxx密钥 / xxx动态码" to get a dynamic code, e.g. "阿里云OTP"
- **Self-service key management**: Send "添加密钥 XXX <secret>" in a private chat to add/update a key in KV
- **No key caching**: Every OTP generation reads KV in real time on the Edge side (binding variable `KV_NAMESPACE`, namespace `TOTP_SERVER`)
- **Card renewal and expiry update**: When the first key expires, the Cloud timer triggers Edge to push a renewed key; when it expires again, the card is marked "expired"
- **Merged management notification**: One request pushes 2 OTPs in total (including the renewal), and the management group card merges them into one (request time / final expiry time / push count)
- **tenant_access_token never travels over APIs**: the token is only fetched, cached and used inside Edge; internal payloads never contain it
- **Encrypted and signed internal communication**: sensitive Edge → Cloud payloads (renewal code / Feishu token) are AES-256-GCM encrypted, then signed with `EDGE_SYNC_SECRET` + HMAC-SHA256 over a canonical JSON envelope, valid for 60 seconds (`createdAt`)

## Project Structure

```
feishu-otp-server/
├── .env                         # Environment variables configuration
├── package.json                 # Node.js project config (dependency: pinyin-pro)
├── edge-functions/
│   ├── api/_shared.js           # Shared utilities: signing / KV / token / base resolution / OTP card (no route)
│   ├── api/feishu_callback.js   # Edge callback entry (route /api/feishu_callback)
├── cloud-functions/
│   └── api/expiry.js            # Cloud scheduled HTTP sender: record + direct Feishu PATCH (route /api/expiry)
└── tests/
    ├── edge_feishu_callback.test.mjs
    └── cloud_expiry.test.mjs
```

## Core Module Description

### edge-functions/api/_shared.js (shared utilities)

- Signing: `canonicalJson` (recursively sorted keys), `signPayload` / `verifyPayload` (HMAC-SHA256, 60 s freshness)
- Sensitive payload encryption: `encryptPayload` / `decryptPayload` (AES-256-GCM, key derived from `EDGE_SYNC_SECRET`)
- Base resolution: `resolveBase` (`EDGE_FUNCTION_BASE` / `CLOUD_FUNCTION_BASE` first, otherwise request same-origin)
- KV read/write and `getTenantAccessToken` (KV-cached, Edge-internal only)
- `generateNewOtp` pre-generates the next-window OTP (`nextCode`); `getTenantAccessToken` returns `{token, expireAt}`
- Unified `json()` responses: `{code:0,data}` / `{code:1,message}`, with `X-Edge-Error*` headers on errors

### edge-functions/api/feishu_callback.js (Edge Function)

- Feishu callback protocol: URL verification, Token/signature verification, AES decryption, timeliness check
- OTP query, private-chat key add, text/card/management notifications
- After sending the OTP card, POSTs a signed `{command:'schedule_tasks', tasks:[{template, data, targetAt}]}` to Cloud `/api/expiry` (tasks carry the pre-generated renewal code and the Feishu auth token with its expiry; absolute timestamps avoid network-delay accumulation)
- The management notification is merged: request time = the request moment, expiry time = the final expiry after renewal, push count = 2

### cloud-functions/api/expiry.js (Cloud Function, scheduled HTTP sender)

- After verifying the signature (`EDGE_SYNC_SECRET`), only records the scheduled tasks (template code + fill data + target time) and returns 200 immediately
- Pre-encoded `TEMPLATES` (`renew_otp` / `expire_message` -> direct Feishu `PATCH`: renewal-code card / expired card) build and send the requests when the absolute timestamps fire
- Receives `{envelope, signature}`: verifies the signature (with `createdAt` freshness) first, then AES-GCM decrypts the task content
- The token is carried by Edge in the task; when missing or about to expire, Cloud refreshes it from env credentials (`FEISHU_APP_ID` / `FEISHU_APP_SECRET`)

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

Covers: Edge callback (GET / URL verification / Token / signature / timeliness / TOTP / pinyin / AES / full OTP flow with signed handoff / key add / group-chat rejection / encrypted events), and Cloud timer (signature verification / record and ack / direct Feishu renewal and expiry PATCH / token refresh when about to expire).

## Contact

If you have any questions or suggestions, feel free to provide feedback through the Gitee platform.
