// ============================================================================
// Edge Function：接收 Cloud Function 的定时指令，由 Edge 调用飞书更新用户 OTP 卡片
// 路由：/api/expire（由文件路径 edge-functions/api/expire.js 决定）
//
// 协议（参考 jufe-eval-flow 通信规范）：
//   POST /api/expire
//   body: { payload: {...}, signature: "<HMAC-SHA256 hex>" }
//   payload 字段：command（"renew_otp" 续期 / "expire_message" 过期）、
//                message_id、user_id、key_name、createdAt
//   校验：EDGE_SYNC_SECRET + canonicalJson(payload)，createdAt 60 秒内有效
//
// tenant_access_token 仅在 Edge 内部使用，不通过 API 传输
// ============================================================================

import { json, verifyPayload, expireFeishuCard, renewFeishuCard } from "./_shared.js";

export default async function onRequest(context) {
  const env = { ...(context.env || {}) };
  const request = context.request;

  if (request.method !== "POST") {
    return json({ code: 1, message: "method not allowed" }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ code: 1, message: "invalid json" }, 400);
  }

  const payload = body && body.payload;
  const signature = body && body.signature;
  const verified = await verifyPayload(payload, signature, env.EDGE_SYNC_SECRET || "");
  if (!verified) {
    console.log("[EXPIRE] 签名校验失败，返回 403");
    return json({ code: 1, message: "signature verification failed" }, 403);
  }

  const { command, message_id: messageId, user_id: userId, key_name: keyName } = payload;
  if (!messageId || !userId) {
    return json({ code: 1, message: "invalid payload" }, 400);
  }

  try {
    if (command === "renew_otp") {
      await renewFeishuCard(env, messageId, userId, keyName || null);
      console.log(`[EXPIRE] OTP 卡片 ${messageId} 已续期新密钥`);
    } else {
      await expireFeishuCard(env, messageId, userId, keyName || null);
      console.log(`[EXPIRE] OTP 卡片 ${messageId} 已过期，状态已更新`);
    }
    return json({ code: 0, data: { ok: true, message_id: messageId, command } });
  } catch (e) {
    console.error(`[EXPIRE] 更新 OTP 卡片失败: ${e}`);
    return json({ code: 1, message: String((e && e.message) || e) }, 500);
  }
}
