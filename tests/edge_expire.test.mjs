// Edge Function /api/expire 测试：Cloud 发来的签名过期指令 -> Edge 调飞书 PATCH 置卡片已失效
// 运行：node tests/edge_expire.test.mjs

import assert from "node:assert/strict";
import onRequest from "../edge-functions/api/expire.js";
import { signPayload } from "../edge-functions/api/_shared.js";

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

const patched = [];
let tokenCalls = 0;

globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url);
  if (u.pathname === "/open-apis/auth/v3/tenant_access_token/internal") {
    tokenCalls += 1;
    return new Response(
      JSON.stringify({ code: 0, tenant_access_token: "FEISHU_TOKEN", expire: 7200 }),
      { status: 200 }
    );
  }
  if (u.pathname.startsWith("/open-apis/im/v1/messages/") && (init.method || "GET") === "PATCH") {
    patched.push(JSON.parse(JSON.parse(init.body).content));
    return new Response(JSON.stringify({ code: 0 }), { status: 200 });
  }
  return new Response(JSON.stringify({ code: -1, msg: `unexpected: ${url}` }), { status: 404 });
};

const env = {
  FEISHU_APP_ID: "app-id",
  FEISHU_APP_SECRET: "app-secret",
  EDGE_SYNC_SECRET: "sync-secret",
};

async function post(payload, signature) {
  const request = new Request("https://totp.camcenter.top/api/expire", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ payload, signature }),
  });
  return onRequest({ request, env });
}

// 1) 合法签名 -> 200，Edge 调飞书 PATCH 已失效卡片，token 仅内部使用
const payload = {
  command: "expire_message",
  message_id: "om_123",
  user_id: "ou_test",
  key_name: "ALIYUN",
  createdAt: Date.now(),
};
const resp = await post(payload, await signPayload(payload, "sync-secret"));
assert.equal(resp.status, 200);
const data = await resp.json();
assert.equal(data.code, 0);
assert.equal(patched.length, 1);
assert.equal(patched[0].header.text_tag_list[0].text.content, "已失效");
assert.match(patched[0].header.title.content, /ALIYUN OTP动态密钥/);
assert.equal(tokenCalls >= 1, true);
assert.ok(kvStore.has("tenant_access_token"));
console.log("1. 合法签名 -> 200 + PATCH 已失效卡片 OK");

// 2) 签名错误 -> 403
const bad = await post(payload, "deadbeef");
assert.equal(bad.status, 403);
console.log("2. 签名错误 -> 403 OK");

// 3) 过期签名（createdAt 超 60 秒）-> 403
const stalePayload = { ...payload, createdAt: Date.now() - 120000 };
const stale = await post(stalePayload, await signPayload(stalePayload, "sync-secret"));
assert.equal(stale.status, 403);
console.log("3. 过期签名 -> 403 OK");

// 4) 缺少必填字段 -> 400
const missingPayload = { command: "expire_message", message_id: "om_x", createdAt: Date.now() };
const missing = await post(missingPayload, await signPayload(missingPayload, "sync-secret"));
assert.equal(missing.status, 400);
console.log("4. 缺少必填字段 -> 400 OK");

// 5) 非 POST -> 405
const getResp = await onRequest({
  request: new Request("https://totp.camcenter.top/api/expire", { method: "GET" }),
  env,
});
assert.equal(getResp.status, 405);
console.log("5. 非 POST -> 405 OK");

// 6) renew_otp 续期：生成新密钥并 PATCH 有效期内卡片
kvStore.set("ALIYUN_TOTP_SECRET", "JBSWY3DPEHPK3PXP");
const renewPayload = {
  command: "renew_otp",
  message_id: "om_456",
  user_id: "ou_test",
  key_name: "ALIYUN",
  createdAt: Date.now(),
};
const renewResp = await post(renewPayload, await signPayload(renewPayload, "sync-secret"));
assert.equal(renewResp.status, 200);
assert.equal(patched.length, 2);
const renewed = patched[1];
assert.equal(renewed.header.text_tag_list[0].text.content, "有效期内");
assert.match(renewed.body.elements[0].columns[0].elements[0].content, /'blue'>\d{6}</);
console.log("6. renew_otp 续期 -> PATCH 新密钥卡片 OK");

console.log();
console.log("ALL EDGE EXPIRE TESTS PASSED");
process.exit(0);
