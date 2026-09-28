# Feishu OTP Server

An One-Time Password (OTP) service implementation for Feishu enterprise applications, running on EdgeOne Makers: **all Feishu business logic runs in an Edge Function**, and a Cloud Function acts only as an expiry timer.

## Architecture and Flow

```
Feishu event ──► Edge Function /api/feishu_callback
                  │
                  ├─ Validation: URL verification / Token / Signature / AES decrypt / timeliness
                  │    (2.0 events read event_type and token from the header)
                  ├─ Routing:
                  │    ├─ im.message.receive_v1     message: query OTP / private-chat key add / help
                  │    ├─ application.bot.menu_v6   custom menu: the event ID is the key identifier;
                  │    │                            ADD_TOTP pushes the self-service add-key card
                  │    └─ card.action.trigger       card callback: write KV synchronously and return the updated card
                  ├─ Send text / TOTP card / form card / audit notification (fetch to Feishu)
                  ├─ Pre-generate the next-window renewal code (codeB) and obtain the Feishu auth token (with expiry)
                  │
                  ├─ After sending the card: AES-256-GCM encrypted + HMAC-signed handoff to Cloud /api/expiry (template code + fill data + target time, carrying codeB and the token)
                  └─ Return 200 to Feishu (card callbacks return a Toast + card JSON)

Cloud Function /api/expiry (scheduled HTTP sender, direct to Feishu)
                  ├─ After signature verification, only records scheduled tasks (template / data / targetAt) and returns 200
                  └─ When the absolute timestamps fire, directly PATCHes Feishu from pre-encoded Cloud templates:
                     renew_otp -> update to the renewal code (still valid); expire_message -> mark expired
                     (refreshes the token from env credentials when it is missing or about to expire)
```

## Key Features

- **TOTP Generation and Query**: Send "xxxTOTP / xxxOTP / xxx验证码 / xxx密钥 / xxx动态码" to get a dynamic code, e.g. "阿里云TOTP" (the legacy "阿里云OTP" form still works)
- **Key management (private-chat commands)**: `添加密钥 XXX <secret/otpauth link>` creates only (refused when it already exists); `更新密钥 XXX <new secret> <password>` updates only; `删除密钥 XXX <password>` deletes the key. Update/delete require `TOTP_ADMIN_PASSWORD` in the environment; when it is not configured they are refused entirely
- **Custom menu events**: A bot custom-menu item's event ID is used directly as the key identifier, so a click pushes the TOTP card (event ID `YUNPAN` -> reads `YUNPAN_TOTP_SECRET`)
- **Self-service add-key from the menu**: The `ADD_TOTP` event ID pushes a form card; the user fills in an identifier and a secret/otpauth link, the backend converts Chinese to pinyin and uppercases the letters before writing KV, and the result card shows three rows "密钥名称 / 添加时间 / 添加人" (no "已保存" wording — the header carries the status); when the identifier already exists nothing is written and the header becomes "TOTP密钥未保存" with an update hint
- **No key caching**: Every OTP generation reads KV in real time on the Edge side (binding variable `KV_NAMESPACE`, namespace `TOTP_SERVER`)
- **Card renewal and expiry update**: When the first key expires, the Cloud timer triggers Edge to push a renewed key; when it expires again, the card is marked "expired"
- **Unified audit log**: after a successful read (TOTP fetch) / create / update / delete, a "TOTP密钥审计日志" card is pushed to the management webhook with operator / action / key name / time / [expiry] / source; a read carries the "expiry" row (final expiry after renewal), and failed or rejected operations are not pushed
- **Key recycle bin**: overwritten / deleted keys are appended to the single KV entry `TOTP_RECYCLE_BIN` (a JSON array with `key` / `value` / `deletedAt` / `operatorId` / `action`); entries older than 90 days are lazily pruned on each write
- **tenant_access_token never travels over APIs**: the token is only fetched, cached and used inside Edge; internal payloads never contain it
- **Encrypted and signed internal communication**: sensitive Edge → Cloud payloads (renewal code / Feishu token) are AES-256-GCM encrypted, then signed with `EDGE_SYNC_SECRET` + HMAC-SHA256 over a canonical JSON envelope, valid for 60 seconds (`createdAt`)

## Project Structure

```
feishu-otp-server/
├── .env                         # Environment variables configuration
├── package.json                 # Node.js project config (dependency: pinyin-pro)
├── edge-functions/
│   ├── api/_shared.js           # Shared utilities: signing / KV / token / base resolution / TOTP card (no route)
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

- Feishu callback protocol: URL verification, Token/signature verification, AES decryption, timeliness check; 2.0 events read `event_type` / `token` from `header` (1.0 top-level fields stay supported)
- Event routing: `im.message.receive_v1` (message), `application.bot.menu_v6` (custom menu), `card.action.trigger` (card callback)
- OTP query, private-chat key management, text/card/audit notifications
- Menu events: `event_key` is normalized by `normalizeIdentifier` and used as the key identifier, reusing the TOTP card flow; the reserved event ID `ADD_TOTP` triggers self-service add-key
- Card callbacks: handled synchronously (response within 3 s), parse `action.form_value`, write KV, and reply `{toast, card:{type:'raw', data}}` to update the card; on validation failure only an error Toast is returned (the original card and typed values stay)
- Identifier normalization `normalizeIdentifier`: Chinese to pinyin, uppercase letters, strip spaces and symbols (`阿里云` / `ali yun` / `ali-yun` -> `ALIYUN`)
- Secret parsing `parseSecretInput`: accepts a raw base32 secret or an `otpauth://` link (reads the `secret` parameter; falls back to the link label when the identifier is empty)
- After sending the TOTP card, POSTs a signed `{command:'schedule_tasks', tasks:[{template, data, targetAt}]}` to Cloud `/api/expiry` (tasks carry the pre-generated renewal code and the Feishu auth token with its expiry; absolute timestamps avoid network-delay accumulation)
- Unified audit notification: read (TOTP fetch, action=读取, time = request moment, expiry = final expiry after renewal) / create / update / delete all push the same audit card; the source distinguishes "私聊命令 / 自定义菜单 / 菜单自助添加"

### cloud-functions/api/expiry.js (Cloud Function, scheduled HTTP sender)

- After verifying the signature (`EDGE_SYNC_SECRET`), only records the scheduled tasks (template code + fill data + target time) and returns 200 immediately
- Pre-encoded `TEMPLATES` (`renew_otp` / `expire_message` -> direct Feishu `PATCH`: renewal-code card / expired card) build and send the requests when the absolute timestamps fire
- Receives `{envelope, signature}`: verifies the signature (with `createdAt` freshness) first, then AES-GCM decrypts the task content
- The token is carried by Edge in the task; when missing or about to expire, Cloud refreshes it from env credentials (`FEISHU_APP_ID` / `FEISHU_APP_SECRET`)

## System Call Flow (event to response)

Every Feishu callback hits the same URL `https://[domain]/api/feishu_callback`, goes through shared validation, and is then routed by event type.

1. **Shared validation**: GET health check; `url_verification` challenge echo; Token check (2.0 events use `header.token`); `x-lark-signature` verification (SHA-256 over `timestamp + nonce + FEISHU_ENCRYPT_KEY + body`); AES-CBC decryption of the `encrypt` field when `FEISHU_ENCRYPT_KEY` is set; message timeliness check.
2. **Message event `im.message.receive_v1`**: `添加密钥 XXX <secret>` creates only (refused when it already exists); `更新密钥 XXX <new secret> <password>` updates only (refused when it does not exist or the password is wrong); `删除密钥 XXX <password>` deletes (refused when it does not exist or the password is wrong); `xxxTOTP / xxxOTP / xxx验证码 / xxx密钥 / xxx动态码` reads KV and builds the TOTP card; anything else returns the help text.
3. **Custom menu event `application.bot.menu_v6`**: `event_key` is the key identifier and reuses the TOTP card flow; `ADD_TOTP` pushes the self-service add-key form card.
4. **Card callback `card.action.trigger`**: form submits are handled synchronously (response within 3 s); on success it replies `{toast, card:{type:'raw', data}}` and shows three rows "密钥名称 / 添加时间 / 添加人"; when the identifier already exists nothing is written and the header shows "TOTP密钥未保存" with an update hint; on validation failure it replies only an error Toast (the audit notification is dispatched via `context.waitUntil`, so it never eats into the 3 s window).
5. **Unified audit**: after a successful read (TOTP fetch) / create / update / delete, a "TOTP密钥审计日志" card is pushed to `MANAGEMENT_WEBHOOK` (operator / action / key name / time / [expiry — read only] / source); failed or rejected operations are not pushed.
6. **After the TOTP card**: renewal/expiry tasks (pre-generated code + token + absolute timestamps) are encrypted, signed and handed to Cloud `/api/expiry`, which PATCHes the card straight to Feishu when due.
7. Message and menu events return 200 immediately and run their logic under `context.waitUntil`; card callbacks must answer synchronously and therefore skip the async branch.

## OTP Key Add and Management Paths

| Path | Entry | Identifier handling | Storage key |
| --- | --- | --- | --- |
| Manual (console) | EdgeOne KV namespace `TOTP_SERVER` | Uppercase letters/digits by hand | `TOTP_SECRET` (default) or `{IDENTIFIER}_TOTP_SECRET` |
| Private-chat command | "添加密钥 XXX <secret/otpauth link>" (create only), "更新密钥 XXX <new secret> <password>" (update only), "删除密钥 XXX <password>" (delete) | `normalizeIdentifier` (Chinese to pinyin, uppercase, strip spaces/symbols) | `{IDENTIFIER}_TOTP_SECRET` |
| Menu self-service | Custom menu `ADD_TOTP` -> form card -> save | Same as above; falls back to the otpauth label when the identifier is empty | `{IDENTIFIER}_TOTP_SECRET` |

- The secret must be base32-decodable before it is written; `ADD_TOTP` is a reserved identifier (normalized to `ADDTOTP`) and cannot be used as a key name.
- No overwrite: "添加密钥" and the menu self-service add are both refused for an existing identifier (they point to "更新密钥"), and only "更新密钥" overwrites the stored value; when the menu add hits an existing identifier the header shows "TOTP密钥未保存".
- Update/delete require the operation password in `TOTP_ADMIN_PASSWORD`; when it is unset they are disallowed entirely, and a wrong password is always rejected (constant-time comparison).
- The `xxxTOTP` query command (legacy `xxxOTP` still accepted) and the menu event ID share one identifier namespace.
- Recycle bin: overwritten / deleted keys are appended to the KV entry `TOTP_RECYCLE_BIN` with `key` (original storage key) / `value` (old value) / `deletedAt` (ms timestamp) / `operatorId` (open_id) / `action` (overwrite or delete); every write first prunes entries older than 90 days (lazy cleanup), and the list can be inspected or restored straight from the KV console.
- Secrets are never cached: every OTP generation reads KV in real time.

## Installation and Configuration

### Requirements

- Node.js 18+ (local development)
- Feishu open platform account and application
- EdgeOne Makers (EdgeOne CLI: `npm install -g edgeone`)

### Environment Variables

```env
FEISHU_APP_ID=your_app_id
FEISHU_APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
# Operation password for update/delete (when unset, update and delete are disabled)
TOTP_ADMIN_PASSWORD=your_operation_password
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
4. Add secrets to KV (users can also add them through the private-chat command or the menu): `TOTP_SECRET` (default), `{UPPERCASE_PINYIN}_TOTP_SECRET` (named, e.g. `YUNPAN_TOTP_SECRET` for identifier `YUNPAN`)
5. Feishu developer console setup:
   - Add `im.message.receive_v1` (message) and `application.bot.menu_v6` (bot custom menu) to the event subscriptions
   - Enable the card callback (`card.action.trigger`) under "Events & Callbacks -> Callback Configuration"; the callback URL is the same as the event URL
   - Add custom-menu items for the bot, choose "push event" as the action, and set the event ID to a key identifier (e.g. `YUNPAN`) or `ADD_TOTP` (self-service add-key)
6. After deployment, the Feishu callback URL stays `https://[your-domain]/api/feishu_callback` (served by the Edge Function)
7. Local development: `npm run dev`; push to the remote repository for automatic build and deployment

Note: the `pinyin-pro` dependency in the Edge Function is bundled via npm (beta). On first deployment, verify with a minimal probe function that dependencies build correctly.

### Local Tests

```bash
npm test
```

Covers: Edge callback (GET / URL verification / Token / signature / timeliness / TOTP / pinyin / AES / full OTP flow with signed handoff / key add / group-chat rejection / encrypted events / custom menu events / self-service add-key card callback), and Cloud timer (signature verification / record and ack / direct Feishu renewal and expiry PATCH / token refresh when about to expire).

## Contact

If you have any questions or suggestions, feel free to provide feedback through the Gitee platform.
