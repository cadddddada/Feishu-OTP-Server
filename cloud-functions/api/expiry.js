// ============================================================================
// EdgeOne Makers Node.js Cloud Function：OTP 卡片过期定时器
// 路由：/api/expiry（由文件路径 cloud-functions/api/expiry.js 决定）
//
// 角色（按业务要求）：
//   1. 只记录需要延时更新的内容（message_id / 续期时刻 / 过期时刻 / 用户 / 密钥名）
//   2. 立即返回 200 确认
//   3. 后台等待任务（等价 Python 等待线程）按绝对时间戳到期后，向 Edge Function 发送
//      签名指令（/api/expire）：renew_at 触发续期（renew_otp），expire_at 触发过期
//      （expire_message），由 Edge 调用飞书更新用户卡片
//
// 使用绝对时间戳而非相对延时：避免 Edge -> Cloud 的网络延时被叠加进等待时间
//
// 全程不接触 tenant_access_token：token 只在 Edge 内部获取与使用，不通过 API 传输。
// 通信签名（参考 jufe-eval-flow 规范）：
//   - 共享密钥 EDGE_SYNC_SECRET，HMAC-SHA256
//   - 签名内容为递归按键名排序的 canonicalJson(payload)
//   - payload 必须包含 createdAt（毫秒），60 秒内有效
// ============================================================================

import crypto from "node:crypto";

// ---------- 签名 ----------
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(",")}}`;
}

function hmacSha256Hex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

function signPayload(payload, secret) {
  return hmacSha256Hex(secret, canonicalJson(payload));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function verifyPayload(payload, signature, secret, maxAgeMs = 60000, maxSkewMs = 5000) {
  if (!secret || !payload || typeof payload.createdAt !== "number") return false;
  const now = Date.now();
  if (now - payload.createdAt > maxAgeMs || payload.createdAt - now > maxSkewMs) return false;
  return safeEqual(signPayload(payload, secret), String(signature || ""));
}

// ---------- 地址前缀解析（EDGE_FUNCTION_BASE 优先，缺省请求同源） ----------
function normalizeHost(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "")
    .replace(/^https?:\/\//i, "");
}

function isLoopbackHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (h === "localhost" || h === "::1" || h === "[::1]" || h === "0.0.0.0") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

function resolveBase(request, env, envVarName) {
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

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

// ---------- 定时任务：按绝对时间戳到期后向 Edge 发送签名指令 ----------
async function runTimedCommand(edgeBase, record, secret, targetAt, command) {
  const wait = Math.max(0, targetAt - Date.now());
  console.log(
    `[EXPIRY] 等待 ${wait}ms 后通知 Edge ${command} ${record.message_id}（目标时刻 ${targetAt}）`
  );
  await new Promise((resolve) => setTimeout(resolve, wait));
  try {
    const payload = {
      command,
      message_id: record.message_id,
      user_id: record.user_id,
      key_name: record.key_name,
      createdAt: Date.now(),
    };
    const signature = signPayload(payload, secret);
    const resp = await fetch(`${edgeBase}/api/expire`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload, signature }),
    });
    console.log(`[EXPIRY] 已通知 Edge ${command} ${record.message_id} status=${resp.status}`);
    if (resp.status !== 200) {
      console.log(`[EXPIRY] Edge 返回异常: ${await resp.text()}`);
    }
  } catch (e) {
    console.error(`[EXPIRY] 通知 Edge 失败: ${e}`);
  }
}

// ---------- 入口 ----------
export default async function onRequest(context) {
  const env = { ...(process.env || {}), ...(context.env || {}) };
  const request = context.request;

  if (request.method !== "POST") {
    return jsonResponse({ code: 1, message: "method not allowed" }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ code: 1, message: "invalid json" }, 400);
  }

  const secret = env.EDGE_SYNC_SECRET || "";
  if (!secret || !verifyPayload(body && body.payload, body && body.signature, secret)) {
    console.log("[EXPIRY] 签名校验失败，返回 403");
    return jsonResponse({ code: 1, message: "signature verification failed" }, 403);
  }

  const p = body.payload;
  const renewAt = Number(p.renew_at);
  const expireAt = Number(p.expire_at);
  if (
    !p.message_id ||
    !Number.isFinite(renewAt) ||
    !Number.isFinite(expireAt) ||
    expireAt < renewAt ||
    !p.user_id
  ) {
    return jsonResponse({ code: 1, message: "invalid payload" }, 400);
  }

  // 仅记录需要延时更新的内容（绝对时间戳），立即确认
  const record = {
    message_id: p.message_id,
    user_id: p.user_id,
    key_name: p.key_name || null,
    renew_at: renewAt,
    expire_at: expireAt,
  };
  const edgeBase = resolveBase(request, env, "EDGE_FUNCTION_BASE");

  // 两个定时任务：renew_at 触发续期，expire_at 触发过期
  const renewTask = runTimedCommand(edgeBase, record, secret, renewAt, "renew_otp");
  const expireTask = runTimedCommand(edgeBase, record, secret, expireAt, "expire_message");
  const task = Promise.allSettled([renewTask, expireTask]);
  if (typeof context.waitUntil === "function") {
    context.waitUntil(task);
  }

  console.log(`[EXPIRY] 已记录定时任务: ${JSON.stringify(record)}`);
  return jsonResponse({
    code: 0,
    data: {
      ok: true,
      message_id: record.message_id,
      renew_at: record.renew_at,
      expire_at: record.expire_at,
    },
  });
}
