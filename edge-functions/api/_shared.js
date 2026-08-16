// ============================================================================
// Edge Function 公共工具（文件名以 _ 开头，不映射路由）
// 参考 jufe-eval-flow 的 edge-functions 通信规范：
//   - 签名密钥：EDGE_SYNC_SECRET（Edge 与 Cloud 配置相同值）
//   - 算法：HMAC-SHA256，签名内容为递归按键名排序的 canonicalJson(payload)
//   - payload 必须包含 createdAt（毫秒），默认 60 秒内有效
//   - 统一响应 { code:0, data } / { code:1, message }，错误带 X-Edge-Error* 头
// 仅使用 Web 标准 API（fetch / Request / Response / crypto.subtle 等）
// ============================================================================

// ---------- 签名 ----------
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(",")}}`;
}

export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))
  );
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function signPayload(payload, secret) {
  return hmacSha256Hex(secret, canonicalJson(payload));
}

export async function verifyPayload(payload, signature, secret, maxAgeMs = 60000, maxSkewMs = 5000) {
  if (!secret || !payload || typeof payload.createdAt !== "number") return false;
  const now = Date.now();
  if (now - payload.createdAt > maxAgeMs || payload.createdAt - now > maxSkewMs) return false;
  const expected = await signPayload(payload, secret);
  return safeEqual(expected, String(signature || ""));
}

// ---------- base32 / TOTP（Web Crypto，等价 pyotp 默认参数） ----------
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input) {
  const s = String(input).toUpperCase().replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of s) {
    if (ch === "=") continue;
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

export async function totp(secret, unixTime = Math.floor(Date.now() / 1000)) {
  const period = 30;
  const digits = 6;
  const counter = Math.floor(unixTime / period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter), false);
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    (sig[offset + 1] << 16) |
    (sig[offset + 2] << 8) |
    sig[offset + 3];
  const code = (binary % 10 ** digits).toString().padStart(digits, "0");
  const remaining = period - (unixTime % period);
  return { code, remaining, expireTs: unixTime + remaining };
}

// 生成当前窗口的 OTP（KV 实时读密钥，不缓存）
export async function generateNewOtp(keyName = null) {
  const kvKey = keyName ? `${keyName}_TOTP_SECRET` : "TOTP_SECRET";
  const secret = await kvGet(kvKey, "");
  if (!secret) return { code: null, remaining: null, expireTs: null, keyName };
  const now = Math.floor(Date.now() / 1000);
  const { code, remaining, expireTs } = await totp(secret, now);
  return { code, remaining, expireTs, keyName };
}

// ---------- 地址前缀解析 ----------
// 优先环境变量（EDGE_FUNCTION_BASE / CLOUD_FUNCTION_BASE），未配置时从请求头推导
export function normalizeHost(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "")
    .replace(/^https?:\/\//i, "");
}

export function isLoopbackHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (h === "localhost" || h === "::1" || h === "[::1]" || h === "0.0.0.0") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

export function resolveBase(request, env, envVarName) {
  const candidates = [];
  const envValue = String(env[envVarName] || "").trim();
  if (envValue) candidates.push(envValue);

  const proto =
    String(request.headers.get("x-forwarded-proto") || "https")
      .trim()
      .replace(/:$/, "") || "https";
  const eoHost = normalizeHost(request.headers.get("eo-pages-host"));
  if (eoHost) candidates.push(`${proto}://${eoHost}`);
  const host = normalizeHost(request.headers.get("host"));
  if (host) candidates.push(`${proto}://${host}`);
  const origin = String(request.headers.get("origin") || "").trim();
  if (origin) candidates.push(origin);
  candidates.push(`${proto}://${host || "localhost"}`);

  for (const c of candidates) {
    const b = String(c).replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(b)) continue;
    try {
      if (!isLoopbackHost(new URL(b).hostname)) return b;
    } catch (e) {
      // 非法 URL，继续尝试下一个候选
    }
  }
  return candidates[0] || `${proto}://${host || "localhost"}`;
}

// ---------- KV（绑定变量直读直写，不缓存密钥） ----------
export async function kvGet(key, defaultValue = null) {
  try {
    console.log(`[KV] get: ${key}`);
    const raw = await KV_NAMESPACE.get(key);
    if (!raw) {
      console.log(`[KV] get: ${key} 不存在`);
      return defaultValue;
    }
    // 快速判断：只有对象/数组/字面量才尝试 JSON.parse，明文密钥（base32）直接返回
    const head = raw.trimStart();
    if (head.startsWith("{") || head.startsWith("[") || head === "null" || head === "true" || head === "false") {
      try {
        return JSON.parse(raw);
      } catch (e) {
        return raw;
      }
    }
    return raw;
  } catch (e) {
    console.log(`[KV] get error: ${e}`);
    return defaultValue;
  }
}

export async function kvPut(key, value) {
  try {
    const valueStr = typeof value === "string" ? value : JSON.stringify(value);
    console.log(`[KV] put: ${key}`);
    await KV_NAMESPACE.put(key, valueStr);
  } catch (e) {
    console.log(`[KV] put error: ${e}`);
  }
}

// ---------- tenant_access_token（KV 缓存 + 实例内内存缓存，仅在 Edge 内部使用） ----------
let _memToken = null;

export async function getTenantAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  // 实例内缓存命中：避免每次请求都读一次 KV
  if (_memToken && now < _memToken.expireAt - 300) {
    return _memToken.token;
  }
  const cached = await kvGet("tenant_access_token");
  if (cached && now < (cached.expire_at || 0) - 300) {
    _memToken = { token: cached.token, expireAt: cached.expire_at };
    return cached.token;
  }
  const resp = await fetch(
    "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: env.FEISHU_APP_ID || "",
        app_secret: env.FEISHU_APP_SECRET || "",
      }),
    }
  );
  const data = await resp.json();
  if (data.code !== 0) throw new Error(`获取 token 失败: ${data.msg}`);
  const token = data.tenant_access_token;
  const expireAt = now + (data.expire || 7200);
  _memToken = { token, expireAt };
  await kvPut("tenant_access_token", { token, expire_at: expireAt });
  return token;
}

// ---------- 已失效卡片与过期更新（由 Edge 调用飞书） ----------
export function buildExpiredCard(userId, keyName) {
  return {
    schema: "2.0",
    config: { update_multi: true },
    body: {
      direction: "vertical",
      elements: [
        {
          tag: "column_set",
          flex_mode: "stretch",
          horizontal_spacing: "8px",
          horizontal_align: "left",
          columns: [
            {
              tag: "column",
              width: "weighted",
              background_style: "blue-50",
              elements: [
                {
                  tag: "markdown",
                  content: "## <font color='orange'>******</font>",
                  text_align: "center",
                },
              ],
              padding: "16px 0px 16px 0px",
              vertical_spacing: "2px",
              horizontal_align: "left",
              vertical_align: "top",
              weight: 1,
            },
          ],
          margin: "0px 0px 0px 0px",
        },
        {
          tag: "markdown",
          content: "**<font color='orange'>剩余时间：已过期</font>**",
          text_align: "center",
          text_size: "normal",
          margin: "0px 0px 0px 0px",
          element_id: "remaining_time",
        },
        {
          tag: "column_set",
          horizontal_spacing: "8px",
          horizontal_align: "left",
          columns: [
            {
              tag: "column",
              width: "auto",
              elements: [
                {
                  tag: "markdown",
                  content: "数据获取人：",
                  text_align: "left",
                  text_size: "heading",
                  margin: "3px 0px 0px 0px",
                },
              ],
              padding: "0px 0px 0px 0px",
              direction: "vertical",
              horizontal_spacing: "8px",
              vertical_spacing: "8px",
              horizontal_align: "left",
              vertical_align: "top",
              margin: "0px 0px 0px 0px",
            },
            {
              tag: "column",
              width: "auto",
              elements: [
                {
                  tag: "person",
                  size: "medium",
                  user_id: userId,
                  margin: "0px 0px 0px 0px",
                },
              ],
              vertical_align: "top",
            },
          ],
          margin: "0px 0px 0px 0px",
        },
      ],
    },
    header: {
      title: {
        tag: "plain_text",
        content: keyName ? `${keyName} OTP动态密钥` : "OTP动态密钥",
      },
      subtitle: { tag: "plain_text", content: "" },
      text_tag_list: [
        {
          tag: "text_tag",
          text: { tag: "plain_text", content: "已失效" },
          color: "red",
        },
      ],
      template: "blue",
      icon: { tag: "standard_icon", token: "lock" },
      padding: "12px 8px 12px 8px",
    },
  };
}

export async function expireFeishuCard(env, messageId, userId, keyName) {
  const token = await getTenantAccessToken(env);
  const url = `https://open.feishu.cn/open-apis/im/v1/messages/${messageId}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ content: JSON.stringify(buildExpiredCard(userId, keyName)) }),
  });
  if (resp.status !== 200) throw new Error(`更新卡片失败: ${await resp.text()}`);
  return resp.json();
}

// ---------- OTP 卡片（有效期内） ----------
export function buildOtpCard(code, remainingSeconds, userId, keyName) {
  return {
    schema: "2.0",
    config: { update_multi: true },
    body: {
      direction: "vertical",
      elements: [
        {
          tag: "column_set",
          flex_mode: "stretch",
          horizontal_spacing: "8px",
          horizontal_align: "left",
          columns: [
            {
              tag: "column",
              width: "weighted",
              background_style: "blue-50",
              elements: [
                {
                  tag: "markdown",
                  content: `## <font color='blue'>${code}</font>`,
                  text_align: "center",
                },
              ],
              padding: "16px 0px 16px 0px",
              vertical_spacing: "2px",
              horizontal_align: "left",
              vertical_align: "top",
              weight: 1,
            },
          ],
          margin: "0px 0px 0px 0px",
        },
        {
          tag: "markdown",
          content: `**<font color='orange'>剩余时间：${remainingSeconds}秒</font>**`,
          text_align: "center",
          text_size: "normal",
          margin: "0px 0px 0px 0px",
          element_id: "remaining_time",
        },
        {
          tag: "column_set",
          horizontal_spacing: "8px",
          horizontal_align: "left",
          columns: [
            {
              tag: "column",
              width: "auto",
              elements: [
                {
                  tag: "markdown",
                  content: "数据获取人：",
                  text_align: "left",
                  text_size: "heading",
                  margin: "3px 0px 0px 0px",
                },
              ],
              padding: "0px 0px 0px 0px",
              direction: "vertical",
              horizontal_spacing: "8px",
              vertical_spacing: "8px",
              horizontal_align: "left",
              vertical_align: "top",
              margin: "0px 0px 0px 0px",
            },
            {
              tag: "column",
              width: "auto",
              elements: [
                {
                  tag: "person",
                  size: "medium",
                  user_id: userId,
                  margin: "0px 0px 0px 0px",
                },
              ],
              vertical_align: "top",
            },
          ],
          margin: "0px 0px 0px 0px",
        },
      ],
    },
    header: {
      title: {
        tag: "plain_text",
        content: keyName ? `${keyName} OTP动态密钥` : "OTP动态密钥",
      },
      subtitle: { tag: "plain_text", content: "" },
      text_tag_list: [
        {
          tag: "text_tag",
          text: { tag: "plain_text", content: "有效期内" },
          color: "green",
        },
      ],
      template: "blue",
      icon: { tag: "standard_icon", token: "lock" },
      padding: "12px 8px 12px 8px",
    },
  };
}

// OTP 续期：重新生成当前窗口密钥并 PATCH 到用户卡片（由 Cloud 定时触发）
export async function renewFeishuCard(env, messageId, userId, keyName) {
  const { code, remaining, expireTs, keyName: resolvedName } = await generateNewOtp(keyName);
  if (!code) throw new Error(`密钥不存在，无法续期: ${keyName || "默认"}`);
  const token = await getTenantAccessToken(env);
  const url = `https://open.feishu.cn/open-apis/im/v1/messages/${messageId}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      content: JSON.stringify(buildOtpCard(code, remaining, userId, resolvedName)),
    }),
  });
  if (resp.status !== 200) throw new Error(`续期更新卡片失败: ${await resp.text()}`);
  return resp.json();
}

// ---------- 统一响应 ----------
export function json(data, status = 200, headers = {}) {
  const h = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  };
  if (status >= 400) {
    h["x-edge-error"] = "1";
    h["x-edge-error-status"] = String(status);
    h["x-edge-error-message"] = encodeURIComponent(String((data && data.message) || "error"));
  }
  return new Response(JSON.stringify(data), { status, headers: h });
}
