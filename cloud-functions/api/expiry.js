// ============================================================================
// EdgeOne Makers Node.js Cloud Function：定时 HTTP 发送器（直连飞书）
// 路由：/api/expiry（由文件路径 cloud-functions/api/expiry.js 决定）
//
// 角色（按业务要求）：
//   1. Edge 通过签名指令指定：在哪个时刻（绝对时间戳 targetAt）发送哪种请求
//      （模板代号 template）以及填充信息（data，含预生成的续期码与飞书鉴权令牌）
//   2. Cloud 只记录任务并立即返回 200 确认
//   3. 后台等待任务（等价 Python 等待线程）按绝对时间戳到期后，直接调用飞书
//      更新/过期用户卡片，不再经过 Edge
//
// 鉴权令牌：Edge 随任务携带 tenant_access_token 与有效期（token_expire_at）；
// Cloud 使用时校验有效期，令牌缺失或临期时用环境凭据（FEISHU_APP_ID/SECRET）
// 自行刷新。全程任务仅在内部签名传输，令牌不过期即用。
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

// ---------- 敏感内容加密/解密（AES-256-GCM，密钥由 EDGE_SYNC_SECRET 派生） ----------
// 与 Edge（Web Crypto）格式兼容：data = base64(密文 || 16 字节认证标签)，iv 12 字节
function encryptPayload(payload, secret) {
  const key = crypto.createHash("sha256").update(secret, "utf8").digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    data: Buffer.concat([enc, cipher.getAuthTag()]).toString("base64"),
    createdAt: Date.now(),
  };
}

function decryptPayload(envelope, secret) {
  const key = crypto.createHash("sha256").update(secret, "utf8").digest();
  const iv = Buffer.from(envelope.iv, "base64");
  const buf = Buffer.from(envelope.data, "base64");
  const tag = buf.subarray(buf.length - 16);
  const data = buf.subarray(0, buf.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

// ---------- 卡片构建（与 Edge 保持一致） ----------
function buildOtpCard(code, remainingSeconds, userId, keyName) {
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

function buildExpiredCard(userId, keyName) {
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

// ---------- 令牌解析：优先用 Edge 携带的令牌，缺失/临期时用环境凭据刷新 ----------
async function resolveToken(data, env) {
  const now = Math.floor(Date.now() / 1000);
  if (data.token && data.token_expire_at && now < data.token_expire_at / 1000 - 300) {
    return data.token;
  }
  console.log("[TASK] 令牌缺失或临期，使用环境凭据刷新");
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
  const result = await resp.json();
  if (result.code !== 0) throw new Error(`获取 token 失败: ${result.msg}`);
  return result.tenant_access_token;
}

// ---------- 预编码模板：Edge 只传模板代号 + 填充信息，请求构造逻辑在 Cloud ----------
const TEMPLATES = {
  renew_otp: {
    method: "PATCH",
    path: (data) => `https://open.feishu.cn/open-apis/im/v1/messages/${data.message_id}`,
    buildBody: async (data, env) => {
      const token = await resolveToken(data, env);
      const remaining = Math.max(
        1,
        Math.floor(((data.code_expire_at || Date.now()) - Date.now()) / 1000)
      );
      const content = buildOtpCard(data.code, remaining, data.user_id, data.key_name || null);
      return {
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ content: JSON.stringify(content) }),
      };
    },
  },
  expire_message: {
    method: "PATCH",
    path: (data) => `https://open.feishu.cn/open-apis/im/v1/messages/${data.message_id}`,
    buildBody: async (data, env) => {
      const token = await resolveToken(data, env);
      const content = buildExpiredCard(data.user_id, data.key_name || null);
      return {
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ content: JSON.stringify(content) }),
      };
    },
  },
};

// ---------- 定时任务：按绝对时间戳到期后直连飞书发送 ----------
async function sendScheduledTask(task, env) {
  const template = TEMPLATES[task.template];
  if (!template) {
    console.error(`[TASK] 未知模板: ${task.template}`);
    return;
  }
  const wait = Math.max(0, task.targetAt - Date.now());
  console.log(`[TASK] 等待 ${wait}ms 后发送 ${task.template}（目标时刻 ${task.targetAt}）`);
  await new Promise((resolve) => setTimeout(resolve, wait));
  try {
    const { headers, body } = await template.buildBody(task.data || {}, env);
    const resp = await fetch(template.path(task.data || {}), {
      method: template.method,
      headers,
      body,
    });
    console.log(`[TASK] 已发送 ${task.template} status=${resp.status}`);
    if (resp.status !== 200) {
      console.log(`[TASK] 飞书返回异常: ${await resp.text()}`);
    }
  } catch (e) {
    console.error(`[TASK] 发送失败: ${e}`);
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
  const envelope = body && body.envelope;
  const signature = body && body.signature;
  if (!secret || !verifyPayload(envelope, signature, secret)) {
    console.log("[TASK] 签名校验失败，返回 403");
    return jsonResponse({ code: 1, message: "signature verification failed" }, 403);
  }

  let p;
  try {
    p = decryptPayload(envelope, secret);
  } catch (e) {
    console.log(`[TASK] 解密失败: ${e}`);
    return jsonResponse({ code: 1, message: "decryption failed" }, 403);
  }

  const tasks = Array.isArray(p.tasks) ? p.tasks : [];
  if (tasks.length === 0) {
    return jsonResponse({ code: 1, message: "invalid payload" }, 400);
  }
  for (const t of tasks) {
    const targetAt = Number(t.targetAt);
    const template = TEMPLATES[t.template];
    const renewMissingCode = t.template === "renew_otp" && !(t.data && t.data.code);
    if (
      !template ||
      !Number.isFinite(targetAt) ||
      !t.data ||
      !t.data.message_id ||
      !t.data.user_id ||
      renewMissingCode
    ) {
      return jsonResponse({ code: 1, message: "invalid payload" }, 400);
    }
  }

  // 仅记录定时任务（模板代号 + 目标时刻 + 填充信息），立即确认
  const record = tasks.map((t) => ({
    template: t.template,
    targetAt: Number(t.targetAt),
    data: t.data,
  }));

  const task = Promise.allSettled(record.map((r) => sendScheduledTask(r, env)));
  if (typeof context.waitUntil === "function") {
    context.waitUntil(task);
  }

  console.log(
    `[TASK] 已记录定时任务: ${JSON.stringify(record.map((r) => ({ template: r.template, targetAt: r.targetAt })))}`
  );
  return jsonResponse({
    code: 0,
    data: {
      ok: true,
      tasks: record.map((r) => ({ template: r.template, targetAt: r.targetAt })),
    },
  });
}

// 供本地测试使用（平台运行时忽略多余导出）
export { encryptPayload, decryptPayload };
