// Edge Function 端到端测试：飞书回调 -> 边缘处理（OTP / 添加密钥）-> 签名转交云函数过期更新
// 运行：node tests/edge_feishu_callback.test.mjs

import assert from "node:assert/strict";
import crypto from "node:crypto";
import onRequest, {
  base32Decode,
  chineseToPinyin,
  parseOtpKey,
  aesDecrypt,
  totp,
} from "../edge-functions/api/feishu_callback.js";
import { verifyPayload } from "../edge-functions/api/_shared.js";

// ==================== Mock 环境 ====================
const kvStore = new Map();
globalThis.KV_NAMESPACE = {
  get: async (k) => (kvStore.has(k) ? kvStore.get(k) : null),
  put: async (k, v) => {
    kvStore.set(k, v);
  },
  delete: async (k) => {
    kvStore.delete(k);
  },
};

const sent = { text: [], cards: [], patches: [], tokenCalls: 0, expiryHandoffs: [], webhooks: [] };

globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url);
  const method = (init.method || "GET").toUpperCase();
  const headers = new Headers(init.headers || {});

  // 云函数过期调度端点（签名转交）
  if (u.pathname === "/api/expiry") {
    const body = JSON.parse(init.body);
    sent.expiryHandoffs.push({
      url: u.origin,
      payload: body.payload,
      signature: body.signature,
    });
    return new Response(JSON.stringify({ code: 0, data: { ok: true } }), { status: 200 });
  }

  // 飞书开放平台
  if (u.pathname === "/open-apis/auth/v3/tenant_access_token/internal") {
    sent.tokenCalls += 1;
    return new Response(
      JSON.stringify({ code: 0, tenant_access_token: "FEISHU_TOKEN", expire: 7200 }),
      { status: 200 }
    );
  }
  if (u.pathname === "/open-apis/im/v1/messages") {
    const body = JSON.parse(init.body);
    if (body.msg_type === "text") {
      sent.text.push(JSON.parse(body.content).text);
      return new Response(JSON.stringify({ code: 0 }), { status: 200 });
    }
    if (body.msg_type === "interactive") {
      sent.cards.push(JSON.parse(body.content));
      return new Response(
        JSON.stringify({ code: 0, data: { message_id: `om_${sent.cards.length}` } }),
        { status: 200 }
      );
    }
  }
  if (u.pathname.startsWith("/open-apis/im/v1/messages/") && method === "PATCH") {
    sent.patches.push(JSON.parse(JSON.parse(init.body).content));
    return new Response(JSON.stringify({ code: 0 }), { status: 200 });
  }
  if (u.hostname.endsWith("webhook")) {
    sent.webhooks.push(JSON.parse(init.body));
    return new Response("ok", { status: 200 });
  }
  return new Response(JSON.stringify({ code: -1, msg: `unexpected: ${url}` }), { status: 404 });
};

const baseEnv = {
  FEISHU_VERIFICATION_TOKEN: "vtok",
  FEISHU_ENCRYPT_KEY: "enc-key",
  FEISHU_APP_ID: "app-id",
  FEISHU_APP_SECRET: "app-secret",
  EDGE_SYNC_SECRET: "sync-secret",
};

function signBody(body, ts = "1700000000", nonce = "123") {
  return crypto
    .createHash("sha256")
    .update(ts + nonce + "enc-key" + body, "utf8")
    .digest("hex");
}

function formatBeijing(unixTs) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    })
      .formatToParts(new Date(unixTs * 1000))
      .map((p) => [p.type, p.value])
  );
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

async function sendEvent(eventData, { env = baseEnv, withSignature = true, ts, nonce } = {}) {
  const body = JSON.stringify(eventData);
  const waitPromises = [];
  const headers = {
    "eo-pages-host": "totp.camcenter.top",
    "x-forwarded-proto": "https",
  };
  if (withSignature) {
    headers["x-lark-request-timestamp"] = ts || "1700000000";
    headers["x-lark-request-nonce"] = nonce || "123";
    headers["x-lark-signature"] = signBody(body, ts, nonce);
  }
  const request = new Request("https://totp.camcenter.top/api/feishu_callback", {
    method: "POST",
    headers,
    body,
  });
  const resp = await onRequest({ request, env, waitUntil: (p) => waitPromises.push(p) });
  await Promise.all(waitPromises);
  return resp;
}

function msgEvent(text, { chatType = "p2p", token = "vtok", createTime } = {}) {
  return {
    type: "im.message.receive_v1",
    token,
    event: {
      sender: { sender_id: { open_id: "ou_test" } },
      message: {
        chat_type: chatType,
        message_id: "om_req",
        content: JSON.stringify({ text }),
        ...(createTime ? { create_time: createTime } : {}),
      },
    },
  };
}

// ==================== 基础功能 ====================
const getResp = await onRequest({
  request: new Request("https://totp.camcenter.top/api/feishu_callback", { method: "GET" }),
  env: baseEnv,
});
assert.equal(getResp.status, 200);
assert.deepEqual(await getResp.json(), { status: "ok" });
console.log("1. GET / -> ok");

const urlResp = await sendEvent(
  { type: "url_verification", token: "vtok", challenge: "ch_abc123" },
  { withSignature: false }
);
assert.equal(urlResp.status, 200);
assert.deepEqual(await urlResp.json(), { challenge: "ch_abc123" });
console.log("2. url_verification -> challenge");

const badTokenResp = await sendEvent(msgEvent("OTP", { token: "wrong" }), {
  withSignature: false,
});
assert.equal(badTokenResp.status, 403);
console.log("3. token mismatch -> 403");

const badSig = await sendEvent(msgEvent("OTP"), { withSignature: false });
assert.equal(badSig.status, 403);
console.log("4. missing signature -> 403");

const expired = await sendEvent(
  msgEvent("OTP", { createTime: String(Date.now() - 60 * 1000) })
);
assert.equal(expired.status, 400);
console.log("5. expired message -> 400");

// ==================== TOTP / 拼音 / 解析 ====================
assert.equal((await totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59)).code, "287082");
assert.equal((await totp("JBSWY3DPEHPK3PXP", 1700000000)).code, "324550");
assert.equal(base32Decode("JBSWY3DPEHPK3PXP").length, 10);
assert.equal(chineseToPinyin("阿里云"), "ALIYUN");
assert.equal(chineseToPinyin("yunpan"), "YUNPAN");
assert.equal(parseOtpKey("阿里云OTP"), "阿里云");
assert.equal(parseOtpKey("OTP"), "");
assert.equal(parseOtpKey("随便聊聊"), null);
console.log("6. TOTP（Web Crypto）+ 拼音 + 解析 OK");

// AES 解密往返
{
  const key = crypto.createHash("sha256").update("enc-key", "utf8").digest();
  const iv = crypto.randomBytes(16);
  const plain = JSON.stringify({ a: 1 });
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const payload = Buffer.concat([iv, enc]).toString("base64");
  assert.equal(await aesDecrypt(payload, "enc-key"), plain);
}
console.log("7. AES 解密（Web Crypto）往返 OK");

// ==================== OTP 查询流程（签名转交云函数） ====================
kvStore.clear();
kvStore.set("TOTP_SECRET", "JBSWY3DPEHPK3PXP");
sent.cards.length = 0;
sent.expiryHandoffs.length = 0;
const otpResp = await sendEvent(msgEvent("OTP"));
assert.equal(otpResp.status, 200);
assert.equal(sent.cards.length, 1);
assert.match(
  sent.cards[0].body.elements[0].columns[0].elements[0].content,
  /^\s*## <font color='blue'>\d{6}<\/font>\s*$/
);
assert.ok(kvStore.has("tenant_access_token"));
assert.equal(sent.expiryHandoffs.length, 1);
const handoff = sent.expiryHandoffs[0];
assert.equal(handoff.url, "https://totp.camcenter.top");
assert.equal(handoff.payload.command, "schedule_expiry");
assert.equal(handoff.payload.message_id, "om_1");
assert.ok(handoff.payload.renew_at > Date.now());
// renew_at = 首次密钥过期后 1 秒；expire_at = 续期密钥过期时刻（再 +29 秒）
assert.equal(handoff.payload.expire_at, handoff.payload.renew_at + 29000);
assert.equal(handoff.payload.user_id, "ou_test");
assert.equal(handoff.payload.key_name, null);
assert.equal(await verifyPayload(handoff.payload, handoff.signature, "sync-secret"), true);
console.log("8. OTP 查询流程 OK（卡片发送 + 签名转交云函数）");

// ==================== 私聊添加密钥 ====================
kvStore.delete("ALIYUN_TOTP_SECRET");
sent.text.length = 0;
await sendEvent(msgEvent("添加密钥 阿里云 JBSWY3DPEHPK3PXP"));
assert.equal(kvStore.get("ALIYUN_TOTP_SECRET"), "JBSWY3DPEHPK3PXP");
assert.ok(sent.text.some((t) => t.includes("ALIYUN_TOTP_SECRET")));
console.log("9. 私聊添加密钥 OK（KV 直写 ALIYUN_TOTP_SECRET）");

const before = kvStore.size;
await sendEvent(msgEvent("添加密钥 测试 INVALID!!!"));
assert.equal(kvStore.size, before);
assert.ok(sent.text.some((t) => t.includes("密钥格式无效")));
console.log("10. 非法密钥拦截 OK");

await sendEvent(msgEvent("添加密钥 阿里云 JBSWY3DPEHPK3PXP", { chatType: "group" }));
assert.ok(sent.text.some((t) => t.includes("仅支持在私聊")));
console.log("11. 群聊拒绝 OK");

// ==================== 加密模式 ====================
{
  const key = crypto.createHash("sha256").update("enc-key", "utf8").digest();
  const iv = crypto.randomBytes(16);
  const plainJson = JSON.stringify(msgEvent("OTP"));
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const enc = Buffer.concat([cipher.update(plainJson, "utf8"), cipher.final()]);
  const encryptedPayload = Buffer.concat([iv, enc]).toString("base64");
  const body = JSON.stringify({ encrypt: encryptedPayload });
  const waitPromises = [];
  const resp = await onRequest({
    request: new Request("https://totp.camcenter.top/api/feishu_callback", {
      method: "POST",
      headers: {
        "eo-pages-host": "totp.camcenter.top",
        "x-lark-request-timestamp": "1700000000",
        "x-lark-request-nonce": "456",
        "x-lark-signature": signBody(body, "1700000000", "456"),
      },
      body,
    }),
    env: baseEnv,
    waitUntil: (p) => waitPromises.push(p),
  });
  await Promise.all(waitPromises);
  assert.equal(resp.status, 200);
  assert.ok(sent.cards.length >= 2);
}
console.log("12. 加密模式事件处理 OK");

// ==================== CLOUD_FUNCTION_BASE 环境变量优先 ====================
kvStore.clear();
kvStore.set("TOTP_SECRET", "JBSWY3DPEHPK3PXP");
sent.expiryHandoffs.length = 0;
await sendEvent(msgEvent("OTP"), {
  env: { ...baseEnv, CLOUD_FUNCTION_BASE: "https://cf.example.com" },
});
assert.equal(sent.expiryHandoffs.length, 1);
assert.equal(sent.expiryHandoffs[0].url, "https://cf.example.com");
assert.equal(sent.expiryHandoffs[0].payload.message_id, "om_3");
console.log("13. CLOUD_FUNCTION_BASE 环境变量优先于请求头 OK");

// ==================== 合并管理通知（一次卡片，覆盖首次请求到最终过期） ====================
sent.webhooks.length = 0;
await sendEvent(msgEvent("OTP"), {
  env: { ...baseEnv, MANAGEMENT_WEBHOOK: "https://mgmt.webhook/hook" },
});
assert.equal(sent.webhooks.length, 1);
const mgmtCard = sent.webhooks[0].card;
const mgmtRows = mgmtCard.body.elements.filter((e) => e.tag === "column_set");
// 卡片不显示推送次数
assert.ok(!mgmtRows.some((r) => r.columns[0].elements[0].content === "推送次数："));
const timeRow = mgmtRows.find((r) => r.columns[0].elements[0].content === "获取时间：");
const expireRow = mgmtRows.find((r) => r.columns[0].elements[0].content === "密钥过期时间：");
assert.ok(timeRow && expireRow);
// 密钥过期时间 = 续期密钥的最终过期时刻（expire_at）
const handoff14 = sent.expiryHandoffs[sent.expiryHandoffs.length - 1];
assert.equal(expireRow.columns[1].elements[0].content, formatBeijing(handoff14.payload.expire_at / 1000));
console.log("14. 管理通知合并（不显示推送次数）OK");

console.log();
console.log("ALL EDGE FUNCTION TESTS PASSED");
process.exit(0);
