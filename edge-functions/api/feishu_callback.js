// ============================================================================
// EdgeOne Makers Edge Function：飞书 OTP 动态密钥查询机器人（回调入口）
// 路由：/api/feishu_callback（由文件路径 edge-functions/api/feishu_callback.js 决定）
//
// 职责：
//   1. 接收飞书事件回调：URL 验证 / Token 校验 / 签名校验 / AES 解密 / 时效校验
//   2. 处理消息：获取 OTP、私聊添加/更新密钥、发送文本与卡片、管理群通知
//   3. KV 直读直写（绑定变量 KV_NAMESPACE，命名空间 TOTP_SERVER），密钥不缓存
//   4. 发送 OTP 卡片后，把过期更新所需数据（message_id / 剩余秒数 / 用户 / 密钥名）
//      通过 HTTP 转交 Cloud Function（/api/expiry），由云函数到点后置卡片为已失效
//
// 依赖：pinyin-pro（npm beta，纯 JS）；TOTP / AES / SHA 使用 Web Crypto
// ============================================================================

import {pinyin} from "pinyin-pro";
import {
    base32Decode,
    buildOtpCard,
    encryptPayload,
    generateNewOtp,
    getTenantAccessToken,
    json,
    kvPut,
    resolveBase,
    safeEqual,
    signPayload,
    totp,
} from "./_shared.js";

// ==================== 拼音转换（pinyin-pro，npm beta） ====================
function chineseToPinyin(text) {
    try {
        const arr = pinyin(String(text), {toneType: "none", type: "array"});
        return arr.join("").toUpperCase();
    } catch (e) {
        return String(text).toUpperCase();
    }
}

async function sendTextMessage(env, receiveId, textContent) {
    const { token } = await getTenantAccessToken(env);
    const url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id";
    await fetch(url, {
        method: "POST",
        headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
        body: JSON.stringify({
            receive_id: receiveId,
            msg_type: "text",
            content: JSON.stringify({text: textContent}),
        }),
    });
}

function sendHelp(env, receiveId) {
    return sendTextMessage(
        env,
        receiveId,
        "发送\u201CxxxOTP\u201D或\u201Cxxx验证码\u201D获取动态密码，例如\u201C阿里云OTP\u201D。\n添加/更新密钥：私聊发送\u201C添加密钥 XXX <密钥>\u201D，例如\u201C添加密钥 阿里云 JBSWY3DPEHPK3PXP\u201D。"
    );
}

// ==================== 卡片构建 ====================
function buildManagementCard(userId, requestTime, expireTimeStr, keyDisplay) {
    const row = (label, content) => ({
        tag: "column_set",
        horizontal_spacing: "8px",
        horizontal_align: "left",
        columns: [
            {
                tag: "column",
                width: "115px",
                elements: [
                    {
                        tag: "markdown",
                        content: label,
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
                elements: [content],
                vertical_align: "top",
            },
        ],
        margin: "0px 0px 0px 0px",
    });

    return {
        schema: "2.0",
        config: {update_multi: true},
        body: {
            direction: "vertical",
            elements: [
                row("数据获取人：", {
                    tag: "person",
                    size: "medium",
                    user_id: userId,
                    margin: "0px 0px 0px 0px",
                }),
                row("获取密钥：", {
                    tag: "markdown",
                    content: keyDisplay,
                    text_align: "left",
                    text_size: "normal",
                    margin: "2px 0px 0px 0px",
                }),
                row("获取时间：", {
                    tag: "markdown",
                    content: requestTime,
                    text_align: "left",
                    text_size: "normal",
                    margin: "2px 0px 0px 0px",
                }),
                row("密钥过期时间：", {
                    tag: "markdown",
                    content: expireTimeStr,
                    text_align: "left",
                    text_size: "normal",
                    margin: "2px 0px 0px 0px",
                })
            ],
        },
        header: {
            title: {tag: "plain_text", content: "OTP动态密钥获取日志"},
            subtitle: {tag: "plain_text", content: ""},
            template: "blue",
            icon: {tag: "standard_icon", token: "lock"},
            padding: "12px 8px 12px 8px",
        },
    };
}

async function sendOtpCard(env, receiveId, code, remainingSeconds, userId, keyName = null, token = null) {
    const bearer = token || (await getTenantAccessToken(env)).token;
    const url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id";
    const resp = await fetch(url, {
        method: "POST",
        headers: {Authorization: `Bearer ${bearer}`, "Content-Type": "application/json"},
        body: JSON.stringify({
            receive_id: receiveId,
            msg_type: "interactive",
            content: JSON.stringify(buildOtpCard(code, remainingSeconds, userId, keyName)),
        }),
    });
    const result = await resp.json();
    if (result.code !== 0) throw new Error(`发送卡片失败: ${result.msg}`);
    return result.data.message_id;
}

async function sendManagementCard(
    env,
    userId,
    requestTime,
    expireTimeStr,
    keyName = null
) {
    const webhook = env.MANAGEMENT_WEBHOOK || "";
    if (!webhook) return;
    const keyDisplay = keyName ? `${keyName} OTP` : "默认 OTP";
    await fetch(webhook, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            msg_type: "interactive",
            card: buildManagementCard(userId, requestTime, expireTimeStr, keyDisplay),
        }),
    });
}

// ==================== OTP 生成 ====================
async function generateOtp(keyName = null) {
    const kvKey = keyName ? `${keyName}_TOTP_SECRET` : "TOTP_SECRET";
    console.log(`[ASYNC] generate_otp: 从 KV 读取密钥 ${kvKey}`);
    const result = await generateNewOtp(keyName);
    if (!result.code) {
        console.log(`[ASYNC] generate_otp: KV 中不存在密钥 ${kvKey}`);
    } else {
        console.log(`[ASYNC] generate_otp: 生成成功 ${kvKey}，剩余 ${result.remaining} 秒`);
    }
    return result;
}

// ==================== 加密 / 校验（Web Crypto） ====================
async function aesDecrypt(encryptedB64, encryptKey) {
    const keyBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(encryptKey));
    const key = await crypto.subtle.importKey("raw", keyBuf, {name: "AES-CBC"}, false, ["decrypt"]);
    const data = Uint8Array.from(atob(encryptedB64), (c) => c.charCodeAt(0));
    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);
    const plain = await crypto.subtle.decrypt({name: "AES-CBC", iv}, key, ciphertext);
    return new TextDecoder().decode(plain);
}

async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyToken(env, token) {
    return safeEqual(String(token || ""), String(env.FEISHU_VERIFICATION_TOKEN || ""));
}

async function verifySignature(env, headers, body) {
    const timestamp = headers.get("x-lark-request-timestamp") || "";
    const nonce = headers.get("x-lark-request-nonce") || "";
    const signature = headers.get("x-lark-signature") || "";
    if (!timestamp || !nonce || !signature) {
        return false;
    }
    const computed = await sha256Hex(
        timestamp + nonce + (env.FEISHU_ENCRYPT_KEY || "") + body
    );
    return safeEqual(computed, String(signature));
}

function checkTimeliness(eventData) {
    const event = eventData.event || {};
    const message = event.message || {};
    let createTimeStr = message.create_time || "";
    if (!createTimeStr) createTimeStr = eventData.create_time || "";
    if (!createTimeStr) {
        return true;
    }
    const createTimeMs = Number(createTimeStr);
    if (!Number.isFinite(createTimeMs)) return true;
    const diff = Date.now() / 1000 - createTimeMs / 1000;
    if (diff < -5) return false;
    if (diff > 30) return false;
    return true;
}

// 复用同一个 Intl 格式化器（构造开销大，避免每个请求重复创建）
const TIME_FORMATTER = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
});

function formatTime(unixTs) {
    const parts = Object.fromEntries(
        TIME_FORMATTER.formatToParts(new Date(unixTs * 1000)).map((p) => [p.type, p.value])
    );
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

// ==================== 定时任务转交云函数（HMAC-SHA256 签名，EDGE_SYNC_SECRET） ====================
// Cloud 是通用定时 HTTP 发送器：Edge 只发送模板代号 + 填充信息 + 目标时刻
async function sendTasksInCloud(env, context, tasks) {
    try {
        const base = resolveBase(context.request, env, "CLOUD_FUNCTION_BASE");
        if (!base) {
            console.log("[EXPIRY] 无法确定 Cloud Function 地址，跳过定时任务转交");
            return;
        }
        // 敏感载荷（续期码 / 飞书令牌）AES-256-GCM 加密后传输，envelope 含 createdAt
        const envelope = await encryptPayload(
            {command: "schedule_tasks", tasks},
            env.EDGE_SYNC_SECRET || ""
        );
        const signature = await signPayload(envelope, env.EDGE_SYNC_SECRET || "");
        const resp = await fetch(`${base}/api/expiry`, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({envelope, signature}),
        });
        console.log(`[EXPIRY] 已转交云函数定时任务: ${tasks.length} 个 status=${resp.status}`);
    } catch (e) {
        console.error(`[EXPIRY] 定时任务转交失败: ${e}`);
    }
}

// ==================== 事件处理 ====================
async function handleEvent(env, context, eventData) {
    const eventType = eventData.type;
    if (eventType === "im.message.receive_v1") {
        await handleMessageEvent(env, context, eventData);
    } else {
        console.log(`[INFO] 忽略未处理的事件类型: ${eventType}`);
    }
}

async function handleMessageEvent(env, context, eventData) {
    try {
        const event = eventData.event || {};
        const message = event.message || {};
        let contentStr = message.content || event.content || "{}";
        let text = "";
        try {
            text = JSON.parse(contentStr).text || "";
        } catch (e) {
            text = "";
        }

        const sender = event.sender || {};
        const senderId = sender.sender_id || {};
        const userId = senderId.open_id || senderId.user_id || sender.open_id;
        if (!userId) {
            console.log("[ERROR] 无法获取用户ID");
            return;
        }

        const chatType = message.chat_type || "";

        // 添加/更新 TOTP 密钥：添加密钥 XXX <密钥>（仅私聊）
        if (await handleAddSecret(env, text, userId, chatType)) {
            return;
        }

        // 解析多密钥格式: xxxOTP / xxx验证码 / xxx密钥 / xxx动态码
        const keyPrefix = parseOtpKey(text);
        if (keyPrefix !== null) {
            const keyName = keyPrefix ? chineseToPinyin(keyPrefix) : null;
            // 并行：KV 读密钥 + TOTP 生成 与 token 获取互不依赖，同时发起
            const otpTask = generateOtp(keyName);
            const tokenTask = getTenantAccessToken(env);
            const [{code, expireTs, keyName: resolvedName, nextCode}, tokenInfo] =
                await Promise.all([otpTask, tokenTask]);
            if (!code) {
                await sendTextMessage(env, userId, "该动态验证码不存在，请检查");
                return;
            }

            const remainingSeconds = Math.max(1, Math.floor(expireTs - Date.now() / 1000));
            const requestTimeStr = formatTime(Math.floor(Date.now() / 1000));
            // 续期：首次密钥在 expireTs 过期，续期后的新密钥再保持一个 TOTP 周期（30 秒）
            const renewAt = expireTs * 1000;
            const expireAt = (expireTs + 30) * 1000;
            const finalExpireTimeStr = formatTime(expireTs + 30);

            // 并行：发送 OTP 卡片 与 合并的管理群通知（2 次推送日志合并）互不依赖；
            // 卡片返回后立即把续期/过期定时任务转交云函数
            const cardTask = sendOtpCard(
                env,
                userId,
                code,
                remainingSeconds,
                userId,
                resolvedName,
                tokenInfo.token
            );
            const mgmtTask = sendManagementCard(
                env,
                userId,
                requestTimeStr,
                finalExpireTimeStr,
                resolvedName
            );
            const messageId = await cardTask;
            console.log(`[ASYNC] 卡片已发送 message_id=${messageId}，转交云函数安排续期与过期`);
            const renewTask = {
                template: "renew_otp",
                data: {
                    message_id: messageId,
                    user_id: userId,
                    key_name: resolvedName || null,
                    code: nextCode,
                    code_expire_at: expireAt,
                    token: tokenInfo.token,
                    token_expire_at: tokenInfo.expireAt * 1000,
                },
                targetAt: renewAt,
            };
            const expireTask = {
                template: "expire_message",
                data: {
                    message_id: messageId,
                    user_id: userId,
                    key_name: resolvedName || null,
                    token: tokenInfo.token,
                    token_expire_at: tokenInfo.expireAt * 1000,
                },
                targetAt: expireAt,
            };
            await sendTasksInCloud(env, context, [renewTask, expireTask]);
            await mgmtTask;

            console.log("[ASYNC] 消息事件处理完成");
        } else {
            await sendHelp(env, userId);
        }
    } catch (e) {
        console.error(`处理消息事件出错: ${e}`);
    }
}

async function handleAddSecret(env, text, userId, chatType = "") {
    const t = String(text || "").trim();
    if (!t.startsWith("添加密钥")) return false;
    if (chatType && chatType !== "p2p") {
        await sendTextMessage(env, userId, "添加密钥仅支持在私聊中使用。");
        return true;
    }
    if (t === "添加密钥" || /^添加密钥\s+\S+\s*$/.test(t)) {
        await sendTextMessage(env, userId, "格式：添加密钥 XXX <密钥>，例如：添加密钥 阿里云 JBSWY3DPEHPK3PXP");
        return true;
    }
    const m = t.match(/^添加密钥\s+(\S+)\s+(\S+)\s*$/);
    if (!m) return false;
    const keyPrefix = m[1];
    const secret = m[2];
    const keyName = chineseToPinyin(keyPrefix);
    const kvKey = `${keyName}_TOTP_SECRET`;
    try {
        base32Decode(secret);
    } catch (e) {
        await sendTextMessage(env, userId, "密钥格式无效（需要 base32 格式），请检查后重试。示例：添加密钥 阿里云 JBSWY3DPEHPK3PXP");
        return true;
    }
    await kvPut(kvKey, secret);
    await sendTextMessage(
        env,
        userId,
        `已添加/更新密钥 ${keyPrefix}（存储键：${kvKey}）。发送\u201C${keyPrefix}OTP\u201D即可获取动态密码。`
    );
    return true;
}

function parseOtpKey(text) {
    const t = String(text || "").trim();
    const m = t.match(/^(.+?)\s*(OTP|验证码|密钥|动态码)$/i);
    if (m) {
        const prefix = m[1].trim();
        return prefix ? prefix : "";
    }
    if (/^(OTP|验证码|密钥|动态码)$/i.test(t)) return "";
    return null;
}

// ==================== 入口 ====================
export default async function onRequest(context) {
    // 边缘函数为 V8 Web 运行时，没有 process 全局对象，环境变量一律从 context.env 读取
    const env = {
        ...(typeof process !== "undefined" ? process.env || {} : {}),
        ...(context.env || {}),
    };
    const request = context.request;

    if (request.method === "GET") {
        return json({status: "ok"});
    }
    if (request.method !== "POST") {
        return json({code: 405, msg: "Method Not Allowed"}, 405);
    }

    const body = await request.text();
    let data;
    try {
        data = JSON.parse(body);
    } catch (e) {
        console.log(`[ERROR] JSON 解析失败: ${e}`);
        return json({code: 400, msg: "Invalid JSON"}, 400);
    }

    let eventData = data;
    if (env.FEISHU_ENCRYPT_KEY && data.encrypt) {
        try {
            const decryptedStr = await aesDecrypt(data.encrypt, env.FEISHU_ENCRYPT_KEY);
            eventData = JSON.parse(decryptedStr);
            if (eventData.schema === "2.0") {
                const header = eventData.header || {};
                eventData.type = header.event_type;
                eventData.token = header.token;
            }
        } catch (e) {
            console.log(`[ERROR] 解密失败: ${e}`);
            return json({code: 500, msg: `Decryption failed: ${e.message}`}, 500);
        }
    }

    if (!(await verifyToken(env, eventData.token))) {
        console.log("[ERROR] Token 验证失败，返回 403");
        return json({code: 403, msg: "Token mismatch"}, 403);
    }

    if (eventData.type === "url_verification") {
        const challenge = eventData.challenge;
        if (challenge) return json({challenge});
        return json({code: 400, msg: "Missing challenge"}, 400);
    }

    if (!(await verifySignature(env, request.headers, body))) {
        console.log("[ERROR] 签名校验失败，返回 403");
        return json({code: 403, msg: "Signature verification failed"}, 403);
    }

    if (!checkTimeliness(eventData)) {
        console.log("[WARN] 消息已过期或来自未来，丢弃");
        return json({code: 400, msg: "Message expired"}, 400);
    }

    // 立即返回 200，后台异步处理业务逻辑
    const task = handleEvent(env, context, eventData).catch((e) =>
        console.error(`[ERROR] 异步事件处理异常: ${e}`)
    );
    if (typeof context.waitUntil === "function") {
        context.waitUntil(task);
    }
    return json({code: 0, msg: "success"});
}

// 供本地测试使用（平台运行时忽略多余导出）
export {base32Decode, chineseToPinyin, parseOtpKey, aesDecrypt, totp};
