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
    appendToRecycleBin,
    base32Decode,
    buildOtpCard,
    encryptPayload,
    generateNewOtp,
    getTenantAccessToken,
    json,
    kvDelete,
    kvGet,
    kvPut,
    personElement,
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

// ==================== 密钥标识符规范化 ====================
// 规则：中文转拼音、英文字母统一大写、剔除空格与符号
// 例："阿里云" / "ali yun" / "ali-yun" -> "ALIYUN"
const ADD_TOTP_EVENT_KEY = "ADD_TOTP";
// 保留标识符：规范化后会剔除下划线，ADD_TOTP -> ADDTOTP
const RESERVED_KEY_NAMES = new Set([ADD_TOTP_EVENT_KEY.replace(/[^0-9A-Za-z]/g, "").toUpperCase()]);
const KEY_NAME_MAX_LENGTH = 64;

function normalizeIdentifier(text) {
    const raw = String(text ?? "").trim();
    if (!raw) return "";
    let converted;
    try {
        converted = pinyin(raw, {toneType: "none", type: "array", v: true}).join("");
    } catch (e) {
        converted = raw;
    }
    return converted.replace(/[^0-9A-Za-z]/g, "").toUpperCase();
}

function safeDecode(value) {
    try {
        return decodeURIComponent(value);
    } catch (e) {
        return value;
    }
}

// 解析密钥输入：支持纯 base32 密钥与 otpauth:// 链接
function parseSecretInput(input) {
    const raw = String(input ?? "").trim();
    if (!raw) return {error: "密钥不能为空"};
    if (/^otpauth:\/\//i.test(raw)) {
        let url;
        try {
            url = new URL(raw);
        } catch (e) {
            return {error: "otpauth 链接格式无效"};
        }
        const secret = (url.searchParams.get("secret") || "").replace(/\s+/g, "").toUpperCase();
        if (!secret) return {error: "otpauth 链接中缺少 secret 参数"};
        const label = safeDecode(String(url.pathname || "").replace(/^\/+/, "")).trim();
        return {secret, label};
    }
    return {secret: raw.replace(/\s+/g, "").toUpperCase()};
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
        "发送\u201Cxxx TOTP\u201D或\u201Cxxx密钥\u201D获取动态密码，例如\u201C阿里云 TOTP\u201D。\n添加密钥：私聊发送\u201C添加密钥 XXX <密钥>\u201D，例如\u201C添加密钥 阿里云 JBSWY3DPEHPK3PXP\u201D。\n更新密钥：私聊发送\u201C更新密钥 XXX <新密钥> <密码>\u201D；删除密钥：私聊发送\u201C删除密钥 XXX <密码>\u201D。\n也可点击机器人自定义菜单「添加密钥」自助添加。"
    );
}

// ==================== 卡片构建 ====================
// 通知卡片行样式：左标签 + 右内容（管理群通知 / 审计日志 / 自助添加结果卡片共用）
// options.align = "center"：人员胶囊等需要与左侧标签垂直居中的内容
function row(label, content, options = {}) {
    const align = options.align || "top";
    return {
        tag: "column_set",
        horizontal_spacing: "8px",
        horizontal_align: "left",
        vertical_align: align,
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
                        margin: align === "center" ? "0px 0px 0px 0px" : "3px 0px 0px 0px",
                    },
                ],
                padding: "0px 0px 0px 0px",
                direction: "vertical",
                horizontal_spacing: "8px",
                vertical_spacing: "8px",
                horizontal_align: "left",
                vertical_align: align,
                margin: "0px 0px 0px 0px",
            },
            {
                tag: "column",
                width: "auto",
                elements: [content],
                vertical_align: align,
            },
        ],
        margin: "0px 0px 0px 0px",
    };
}

async function sendInteractiveCard(env, receiveId, card, token = null) {
    const bearer = token || (await getTenantAccessToken(env)).token;
    const url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id";
    const resp = await fetch(url, {
        method: "POST",
        headers: {Authorization: `Bearer ${bearer}`, "Content-Type": "application/json"},
        body: JSON.stringify({
            receive_id: receiveId,
            msg_type: "interactive",
            content: JSON.stringify(card),
        }),
    });
    const result = await resp.json();
    if (result.code !== 0) throw new Error(`发送卡片失败: ${result.msg}`);
    return result.data.message_id;
}

async function sendOtpCard(env, receiveId, code, remainingSeconds, userId, keyName = null, token = null) {
    return sendInteractiveCard(
        env,
        receiveId,
        buildOtpCard(code, remainingSeconds, userId, keyName),
        token
    );
}

// ==================== 密钥操作审计通知（Webhook） ====================
// 读取（获取 TOTP）/ 新建 / 更新 / 删除成功后推送一张审计卡片到管理群，统一作为审计日志
const AUDIT_TEMPLATES = {读取: "blue", 新建: "green", 更新: "orange", 删除: "red"};

function buildAuditCard(action, keyName, userId, timeStr, source, expireTimeStr = null) {
    const value = (content) => ({
        tag: "markdown",
        content,
        text_align: "left",
        text_size: "normal",
        margin: "2px 0px 0px 0px",
    });
    const elements = [
        row("操作人：", personElement(userId), {align: "center"}),
        row("操作类型：", value(action)),
        row("密钥名称：", value(keyName)),
        row("操作时间：", value(timeStr)),
    ];
    if (expireTimeStr) {
        elements.push(row("过期时间：", value(expireTimeStr)));
    }
    elements.push(row("操作来源：", value(source)));
    return {
        schema: "2.0",
        config: {update_multi: true},
        body: {direction: "vertical", elements},
        header: {
            title: {tag: "plain_text", content: "TOTP密钥审计日志"},
            subtitle: {tag: "plain_text", content: ""},
            template: AUDIT_TEMPLATES[action] || "blue",
            padding: "12px 8px 12px 8px",
        },
    };
}

async function sendAuditNotification(env, action, keyName, userId, source, expireTimeStr = null) {
    const webhook = env.MANAGEMENT_WEBHOOK || "";
    if (!webhook) {
        console.log(`[AUDIT] 未配置 MANAGEMENT_WEBHOOK，跳过 ${action} ${keyName}`);
        return;
    }
    try {
        const timeStr = formatTime(Math.floor(Date.now() / 1000));
        await fetch(webhook, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                msg_type: "interactive",
                card: buildAuditCard(action, keyName, userId, timeStr, source, expireTimeStr),
            }),
        });
        console.log(`[AUDIT] ${action} ${keyName} by ${userId || "unknown"}（${source}）`);
    } catch (e) {
        console.error(`[AUDIT] 审计通知失败: ${e}`);
    }
}

// ==================== 自助添加密钥卡片 ====================
// 菜单事件 ADD_TOTP 触发的表单卡片（卡片 JSON 2.0，form 必须直接挂在 body 下）
function buildAddTotpCard() {
    return {
        schema: "2.0",
        config: {update_multi: true},
        body: {
            direction: "vertical",
            elements: [
                {
                    tag: "markdown",
                    content: "填写密钥标识符与密钥，点击「保存」提交",
                    text_size: "normal",
                    margin: "0px 0px 0px 0px",
                },
                {
                    tag: "form",
                    name: "add_totp_form",
                    direction: "vertical",
                    elements: [
                        {
                            tag: "input",
                            name: "identifier",
                            label: {tag: "plain_text", content: "密钥标识符"},
                            placeholder: {tag: "plain_text", content: ""},
                            required: true,
                            input_type: "text",
                            width: "fill",
                            max_length: 64,
                        },
                        {
                            tag: "input",
                            name: "secret",
                            label: {tag: "plain_text", content: "密钥 / otpauth 链接"},
                            placeholder: {
                                tag: "plain_text",
                                content: "",
                            },
                            required: true,
                            input_type: "text",
                            width: "fill",
                        },
                        {
                            tag: "button",
                            name: "submit",
                            text: {tag: "plain_text", content: "保存"},
                            type: "primary_filled",
                            width: "fill",
                            form_action_type: "submit",
                        },
                    ],
                },
            ],
        },
        header: {
            title: {tag: "plain_text", content: "添加TOTP密钥"},
            subtitle: {tag: "plain_text", content: ""},
            template: "blue",
            padding: "12px 8px 12px 8px",
        },
    };
}

function buildSavedCard(keyName, timeStr, userId = null, saved = true) {
    const elements = [
        row("密钥名称：", {
            tag: "markdown",
            content: keyName,
            text_align: "left",
            text_size: "normal",
            margin: "2px 0px 0px 0px",
        }),
        row("添加时间：", {
            tag: "markdown",
            content: timeStr,
            text_align: "left",
            text_size: "normal",
            margin: "2px 0px 0px 0px",
        }),
    ];
    if (userId) {
        elements.push(row("添加人：", personElement(userId), {align: "center"}));
    }
    elements.push({
        tag: "markdown",
        content: saved
            ? `发送「${keyName} TOTP」即可获取动态密码。`
            : `标识符 ${keyName} 已被占用，本次未保存；如需更新请发送「更新密钥 ${keyName} <密钥> <密码>」；如需删除请发送「删除密钥 ${keyName} <密码>」。`,
        text_size: "normal",
        margin: "8px 0px 0px 0px",
    });
    return {
        schema: "2.0",
        config: {update_multi: true},
        body: {direction: "vertical", elements},
        header: {
            title: {tag: "plain_text", content: saved ? "TOTP密钥已保存" : "TOTP密钥未保存"},
            subtitle: {tag: "plain_text", content: ""},
            template: saved ? "green" : "orange",
            padding: "12px 8px 12px 8px",
        },
    };
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
    } else if (eventType === "application.bot.menu_v6") {
        await handleMenuEvent(env, context, eventData);
    } else {
        console.log(`[INFO] 忽略未处理的事件类型: ${eventType}`);
    }
}

// 自定义菜单事件：事件 ID 即密钥标识符（菜单事件 ID = YUNPAN 时读取 YUNPAN_TOTP_SECRET）
// 例外：事件 ID = ADD_TOTP 时推送自助添加密钥卡片
async function handleMenuEvent(env, context, eventData) {
    try {
        const event = eventData.event || {};
        const operator = event.operator || {};
        const operatorId = operator.operator_id || {};
        const userId = operatorId.open_id || operator.open_id || operatorId.user_id;
        const eventKey = String(event.event_key || "").trim();
        if (!userId) {
            console.log("[ERROR] 菜单事件无法获取用户ID");
            return;
        }
        const keyName = normalizeIdentifier(eventKey);
        if (!keyName) {
            await sendHelp(env, userId);
            return;
        }
        if (RESERVED_KEY_NAMES.has(keyName)) {
            await sendInteractiveCard(env, userId, buildAddTotpCard());
            console.log("[MENU] 已推送自助添加密钥卡片");
            return;
        }
        console.log(`[MENU] 菜单事件 ${eventKey} -> 密钥标识符 ${keyName}`);
        await sendOtpForKey(env, context, userId, keyName, "自定义菜单");
    } catch (e) {
        console.error(`处理菜单事件出错: ${e}`);
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

        // 密钥指令：添加密钥（仅新增）/ 更新密钥（仅更新），仅私聊
        if (await handleSecretCommand(env, text, userId, chatType)) {
            return;
        }

        // 解析多密钥格式: xxxTOTP / xxxOTP / xxx验证码 / xxx密钥 / xxx动态码
        const keyPrefix = parseOtpKey(text);
        if (keyPrefix !== null) {
            const keyName = keyPrefix ? normalizeIdentifier(keyPrefix) || null : null;
            await sendOtpForKey(env, context, userId, keyName);
        } else {
            await sendHelp(env, userId);
        }
    } catch (e) {
        console.error(`处理消息事件出错: ${e}`);
    }
}

// 生成 OTP 卡片并按绝对时间戳安排续期/过期（消息事件与菜单事件共用）
async function sendOtpForKey(env, context, userId, keyName, source = "私聊命令") {
    // 并行：KV 读密钥 + TOTP 生成 与 token 获取互不依赖，同时发起
    const otpTask = generateOtp(keyName);
    const tokenTask = getTenantAccessToken(env);
    const [{code, expireTs, keyName: resolvedName, nextCode}, tokenInfo] =
        await Promise.all([otpTask, tokenTask]);
    if (!code) {
        await sendTextMessage(env, userId, "该动态验证码不存在，请检查");
        return false;
    }

    const remainingSeconds = Math.max(1, Math.floor(expireTs - Date.now() / 1000));
    // 续期：首次密钥在 expireTs 过期，续期后的新密钥再保持一个 TOTP 周期（30 秒）
    const renewAt = expireTs * 1000;
    const expireAt = (expireTs + 30) * 1000;
    const finalExpireTimeStr = formatTime(expireTs + 30);

    // 并行：发送 OTP 卡片 与 读取审计（获取时间 / 续期后最终过期时间）互不依赖；
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
    const auditTask = sendAuditNotification(
        env,
        "读取",
        resolvedName || "默认",
        userId,
        source,
        finalExpireTimeStr
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
    await auditTask;

    console.log("[ASYNC] OTP 卡片处理完成");
    return true;
}

// 回收站：被覆盖 / 删除的旧密钥统一追加到 TOTP_RECYCLE_BIN（写入失败不影响主流程）
async function archiveSecret(kvKey, value, userId, action) {
    const record = {
        key: kvKey,
        value: typeof value === "string" ? value : JSON.stringify(value ?? ""),
        deletedAt: Date.now(),
        operatorId: userId || null,
        action,
    };
    if (!(await appendToRecycleBin([record]))) {
        console.error(`[RECYCLE] 回收站写入失败: ${kvKey}`);
    }
}

// 密钥指令（仅私聊）：
//   添加密钥 XXX <密钥>            仅新增，已存在不覆盖
//   更新密钥 XXX <新密钥> <密码>    仅更新，需操作密码 env.TOTP_ADMIN_PASSWORD
//   删除密钥 XXX <密码>            删除，需操作密码 env.TOTP_ADMIN_PASSWORD
async function handleSecretCommand(env, text, userId, chatType = "") {
    const t = String(text || "").trim();
    const cmd = ["添加密钥", "更新密钥", "删除密钥"].find((c) => t === c || t.startsWith(`${c} `));
    if (!cmd) return false;
    if (chatType && chatType !== "p2p") {
        await sendTextMessage(env, userId, "密钥管理仅支持在私聊中使用。");
        return true;
    }
    const isAdd = cmd === "添加密钥";
    const isUpdate = cmd === "更新密钥";
    const usage = isAdd
        ? `${cmd} XXX <密钥>`
        : isUpdate
            ? `${cmd} XXX <新密钥> <密码>`
            : `${cmd} XXX <密码>`;
    const example = isAdd
        ? `${cmd} 阿里云 JBSWY3DPEHPK3PXP`
        : isUpdate
            ? `${cmd} 阿里云 JBSWY3DPEHPK3PXP <密码>`
            : `${cmd} 阿里云 <密码>`;
    const parts = t.slice(cmd.length).trim().split(/\s+/).filter(Boolean);
    if (parts.length !== (isUpdate ? 3 : 2)) {
        await sendTextMessage(env, userId, `格式：${usage}，例如：${example}`);
        return true;
    }

    // 更新/删除需要操作密码；系统未配置密码时一律禁止
    if (!isAdd) {
        const opPassword = String(env.TOTP_ADMIN_PASSWORD || "");
        const inputPassword = isUpdate ? parts[2] : parts[1];
        if (!opPassword) {
            console.log("[SECRET] 未配置 TOTP_ADMIN_PASSWORD，拒绝更新/删除");
            await sendTextMessage(env, userId, "系统未配置操作密码（TOTP_ADMIN_PASSWORD），已禁止更新/删除密钥。");
            return true;
        }
        if (!safeEqual(inputPassword, opPassword)) {
            console.log(`[SECRET] 操作密码错误，拒绝 ${cmd}`);
            await sendTextMessage(env, userId, "操作密码错误，已拒绝执行。");
            return true;
        }
    }

    const keyName = normalizeIdentifier(parts[0]);
    if (!keyName) {
        await sendTextMessage(env, userId, "标识符无效（需包含中文、字母或数字），请检查后重试。");
        return true;
    }
    if (RESERVED_KEY_NAMES.has(keyName)) {
        await sendTextMessage(env, userId, `标识符 ${ADD_TOTP_EVENT_KEY} 为系统保留字，请更换。`);
        return true;
    }
    const kvKey = `${keyName}_TOTP_SECRET`;
    const oldValue = await kvGet(kvKey, "");
    const exists = Boolean(oldValue);
    if (isAdd && exists) {
        await sendTextMessage(env, userId, `标识符 ${keyName} 已存在，未添加。如需更新请发送\u201C更新密钥 ${keyName} <新密钥> <密码>\u201D。`);
        return true;
    }
    if (!isAdd && !exists) {
        await sendTextMessage(env, userId, `标识符 ${keyName} 不存在，请先发送\u201C添加密钥 ${keyName} <密钥>\u201D添加。`);
        return true;
    }

    // 删除：密码校验通过后直接删除
    if (cmd === "删除密钥") {
        if (!(await kvDelete(kvKey))) {
            await sendTextMessage(env, userId, "密钥删除失败，请稍后重试。");
            return true;
        }
        await archiveSecret(kvKey, oldValue, userId, "删除");
        await sendAuditNotification(env, "删除", keyName, userId, "私聊命令");
        await sendTextMessage(env, userId, `已删除密钥 ${keyName}（存储键：${kvKey}）。`);
        return true;
    }

    const parsed = parseSecretInput(parts[1]);
    if (parsed.error) {
        await sendTextMessage(env, userId, `${parsed.error}。示例：${example}`);
        return true;
    }
    try {
        base32Decode(parsed.secret);
    } catch (e) {
        await sendTextMessage(env, userId, `密钥格式无效（需要 base32 格式），请检查后重试。示例：${example}`);
        return true;
    }
    if (!(await kvPut(kvKey, parsed.secret))) {
        await sendTextMessage(env, userId, "密钥保存失败，请稍后重试。");
        return true;
    }
    if (!isAdd) {
        // 覆盖前先把旧密钥存入回收站
        await archiveSecret(kvKey, oldValue, userId, "覆盖");
    }
    await sendAuditNotification(env, isAdd ? "新建" : "更新", keyName, userId, "私聊命令");
    await sendTextMessage(
        env,
        userId,
        `已${isAdd ? "添加" : "更新"}密钥 ${keyName}（存储键：${kvKey}）。发送\u201C${keyName} TOTP\u201D即可获取动态密码。`
    );
    return true;
}

// ==================== 卡片回调（card.action.trigger） ====================
// 表单提交：标识符规范化（中文转拼音、统一大写）+ 密钥/otpauth 解析 + 写 KV，
// 响应体直接返回更新后的卡片（3 秒内同步响应）
async function handleCardAction(env, context, eventData) {
    const event = eventData.event || {};
    const action = event.action || {};
    const operator = event.operator || {};
    const userId = operator.open_id || operator.user_id || null;
    const formValue = action.form_value;
    console.log(`[CARD] 收到卡片交互 tag=${action.tag || ""} name=${action.name || ""}`);
    if (action.tag === "button" && formValue && typeof formValue === "object") {
        return await handleAddTotpSubmit(env, formValue, userId, context);
    }
    return {toast: {type: "info", content: "暂不支持的操作"}};
}

async function handleAddTotpSubmit(env, formValue, userId = null, context = null) {
    const values = formValue && typeof formValue === "object" ? formValue : {};
    const identifierRaw = String(values.identifier ?? "").trim();
    const parsed = parseSecretInput(values.secret);
    if (parsed.error) {
        // 仅返回 Toast 时飞书保持原卡片（用户已填内容不丢失），便于修正后重新提交
        return {toast: {type: "error", content: parsed.error}};
    }
    let keyName = normalizeIdentifier(identifierRaw);
    if (!keyName && parsed.label) keyName = normalizeIdentifier(parsed.label);
    if (!keyName) {
        return {toast: {type: "error", content: "标识符不能为空（可填英文或中文，系统会转为大写拼音）"}};
    }
    if (RESERVED_KEY_NAMES.has(keyName)) {
        return {toast: {type: "error", content: `标识符 ${ADD_TOTP_EVENT_KEY} 为系统保留字，请更换`}};
    }
    if (keyName.length > KEY_NAME_MAX_LENGTH) {
        return {toast: {type: "error", content: `标识符过长（最多 ${KEY_NAME_MAX_LENGTH} 个字符）`}};
    }
    try {
        base32Decode(parsed.secret);
    } catch (e) {
        return {toast: {type: "error", content: "密钥格式无效（需要 base32 格式），请检查后重试"}};
    }
    const kvKey = `${keyName}_TOTP_SECRET`;
    const timeStr = formatTime(Math.floor(Date.now() / 1000));
    // 已有同名标识符时不覆盖，仅回显“未保存”
    if (await kvGet(kvKey, "")) {
        console.log(`[CARD] 标识符已存在，未保存: ${kvKey}`);
        return {
            toast: {type: "warning", content: "标识符已存在，未保存"},
            card: {type: "raw", data: buildSavedCard(keyName, timeStr, userId, false)},
        };
    }
    if (!(await kvPut(kvKey, parsed.secret))) {
        return {toast: {type: "error", content: "密钥保存失败，请稍后重试"}};
    }
    console.log(`[CARD] 自助添加密钥成功: ${kvKey}`);
    // 审计通知不阻塞卡片回调（3 秒内必须响应）：有 waitUntil 时交给运行时托管
    const auditTask = sendAuditNotification(env, "新建", keyName, userId, "菜单自助添加");
    if (context && typeof context.waitUntil === "function") {
        context.waitUntil(auditTask);
    } else {
        await auditTask;
    }
    return {
        toast: {type: "success", content: "已保存"},
        card: {type: "raw", data: buildSavedCard(keyName, timeStr, userId)},
    };
}

function parseOtpKey(text) {
    const t = String(text || "").trim();
    const m = t.match(/^(.+?)\s*(TOTP|OTP|验证码|密钥|动态码)$/i);
    if (m) {
        const prefix = m[1].trim();
        return prefix ? prefix : "";
    }
    if (/^(TOTP|OTP|验证码|密钥|动态码)$/i.test(t)) return "";
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

    // 飞书 2.0 事件（自定义菜单 / 卡片回调 / 消息事件）把事件类型与校验 Token 放在 header 中
    if (eventData && eventData.header) {
        if (!eventData.type) eventData.type = eventData.header.event_type;
        if (!eventData.token) eventData.token = eventData.header.token;
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

    // 卡片回调必须同步响应（3 秒内返回 Toast / 更新后的卡片），不走异步分支
    if (eventData.type === "card.action.trigger") {
        let view;
        try {
            view = await handleCardAction(env, context, eventData);
        } catch (e) {
            console.error(`[ERROR] 卡片回调处理失败: ${e}`);
            view = {toast: {type: "error", content: "处理失败，请稍后重试"}};
        }
        return json(view);
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
export {base32Decode, chineseToPinyin, parseOtpKey, aesDecrypt, totp, normalizeIdentifier, parseSecretInput, handleAddTotpSubmit};
