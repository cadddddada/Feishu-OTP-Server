// Cloud Function 测试：接收签名调度 -> 仅记录并立即确认 200 -> 到期后向 Edge 发送签名过期指令
// 运行：node tests/cloud_expiry.test.mjs

import assert from "node:assert/strict";
import crypto from "node:crypto";
import onRequest from "../cloud-functions/api/expiry.js";

// ---------- 测试侧签名工具（与云函数一致） ----------
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(",")}}`;
}

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret).update(canonicalJson(payload), "utf8").digest("hex");
}

function verify(payload, signature, secret) {
  const expected = sign(payload, secret);
  return expected.length === String(signature).length && crypto.timingSafeEqual(
    Buffer.from(expected, "utf8"),
    Buffer.from(String(signature), "utf8")
  );
}

// ---------- Mock：只允许 Cloud 调用 Edge /api/expire ----------
const edgeCalls = [];
globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url);
  if (u.pathname === "/api/expire") {
    const body = JSON.parse(init.body);
    edgeCalls.push({ url: u.origin, payload: body.payload, signature: body.signature });
    return new Response(JSON.stringify({ code: 0, data: { ok: true } }), { status: 200 });
  }
  throw new Error(`Cloud 不应调用其他地址: ${url}`);
};

const env = {
  EDGE_SYNC_SECRET: "sync-secret",
};

async function post(payload, { signature, env: envOverride } = {}) {
  const waitPromises = [];
  const request = new Request("https://totp.camcenter.top/api/expiry", {
    method: "POST",
    headers: { "content-type": "application/json", "eo-pages-host": "totp.camcenter.top" },
    body: JSON.stringify({ payload, signature: signature || sign(payload, "sync-secret") }),
  });
  const resp = await onRequest({
    request,
    env: { ...env, ...(envOverride || {}) },
    waitUntil: (p) => waitPromises.push(p),
  });
  await Promise.all(waitPromises);
  return resp;
}

// 1) 合法调度 -> 立即 200 确认；定时到期后向 Edge 发签名 expire_message 指令（无 token、无 KV）
const schedule = {
  command: "schedule_expiry",
  message_id: "om_123",
  renew_at: Date.now(),
  expire_at: Date.now() + 10,
  user_id: "ou_test",
  key_name: "ALIYUN",
  createdAt: Date.now(),
};
const resp = await post(schedule, { env: { EDGE_FUNCTION_BASE: "https://ef.example.com" } });
assert.equal(resp.status, 200);
const data = await resp.json();
assert.equal(data.code, 0);
assert.equal(data.data.message_id, "om_123");
assert.equal(typeof data.data.renew_at, "number");
assert.equal(typeof data.data.expire_at, "number");
assert.equal(edgeCalls.length, 2);
assert.deepEqual(
  edgeCalls.map((c) => c.payload.command).sort(),
  ["expire_message", "renew_otp"]
);
for (const call of edgeCalls) {
  assert.equal(call.url, "https://ef.example.com");
  assert.equal(call.payload.message_id, "om_123");
  assert.equal(call.payload.user_id, "ou_test");
  assert.equal(call.payload.key_name, "ALIYUN");
  assert.equal(verify(call.payload, call.signature, "sync-secret"), true);
}
console.log("1. 立即确认 200 + 按绝对时间戳发续期/过期签名指令 OK");

// 2) 签名错误 -> 403
const bad = await post(schedule, { signature: "deadbeef" });
assert.equal(bad.status, 403);
console.log("2. 签名错误 -> 403 OK");

// 3) 过期签名（createdAt 超 60 秒）-> 403
const stale = await post({ ...schedule, createdAt: Date.now() - 120000 });
assert.equal(stale.status, 403);
console.log("3. 过期签名 -> 403 OK");

// 4) 参数缺失 -> 400
const invalid = await post({ command: "schedule_expiry", message_id: "x", createdAt: Date.now() });
assert.equal(invalid.status, 400);
console.log("4. 参数缺失 -> 400 OK");

// 5) 非 POST -> 405
const getResp = await onRequest({
  request: new Request("https://totp.camcenter.top/api/expiry", { method: "GET" }),
  env,
});
assert.equal(getResp.status, 405);
console.log("5. 非 POST -> 405 OK");

// 6) 未配置 EDGE_FUNCTION_BASE -> 从请求头推导同源地址
edgeCalls.length = 0;
await post({ ...schedule, message_id: "om_456" });
assert.equal(edgeCalls.length, 2);
assert.ok(edgeCalls.every((c) => c.url === "https://totp.camcenter.top"));
console.log("6. 缺省 EDGE_FUNCTION_BASE -> 请求同源 OK");

console.log();
console.log("ALL CLOUD EXPIRY TESTS PASSED");
process.exit(0);
