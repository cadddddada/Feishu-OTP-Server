# Feishu OTP Server

提供给飞书企业应用的一次性密码（OTP）服务实现，运行在 EdgeOne Makers 上：**飞书业务全部由 Edge Function 处理，Cloud Function 仅作为过期更新定时器**。

## 架构与流程

```
飞书事件 ──► Edge Function /api/feishu_callback
                  │
                  ├─ 校验：URL 验证 / Token / 签名 / AES 解密 / 时效
                  ├─ 处理消息：获取 OTP（KV 直读 + TOTP）、私聊添加/更新密钥
                  ├─ 发送文本 / OTP 卡片 / 管理群通知（fetch 调飞书，token 仅在 Edge 内部）
                  │
                  ├─ 发卡片后：HMAC 签名转交 Cloud /api/expiry（schedule_expiry，含绝对时间戳）
                  └─ 返回 200 给飞书

Cloud Function /api/expiry（仅定时器角色）
                  ├─ 验签通过后仅记录 {message_id, renew_at, expire_at, user_id, key_name}，立即返回 200
                  └─ 两个后台定时任务按绝对时间戳触发，向 Edge /api/expire 发送 HMAC 签名指令：
                     renew_at -> renew_otp（续期推送新密钥）；expire_at -> expire_message（置为已失效）

Edge Function /api/expire
                  ├─ renew_otp：重新生成 OTP 并 PATCH 用户卡片（新密钥，有效期内）
                  └─ expire_message：PATCH 卡片为“已失效”
```

## 主要功能

- **OTP 生成与查询**：发送“xxxOTP / xxx验证码 / xxx密钥 / xxx动态码”获取动态密码，例如“阿里云OTP”
- **密钥自助添加/更新**：私聊发送“添加密钥 XXX <密钥>”写入/更新 KV，例如“添加密钥 阿里云 JBSWY3DPEHPK3PXP”
- **密钥不缓存**：每次生成 OTP 都在 Edge 侧实时读取 KV（绑定变量 `KV_NAMESPACE`，命名空间 `TOTP_SERVER`）
- **卡片续期与过期更新**：首次密钥过期时 Cloud 定时触发 Edge 续期推送新密钥，再次过期后置为“已失效”
- **合并管理通知**：一次请求累计推送 2 次 OTP（含续期），管理群卡片合并为一条（获取时间 / 最终过期时间 / 推送次数）
- **tenant_access_token 不经过 API**：token 只在 Edge 内部获取、缓存与使用，Edge/Cloud 通信载荷中不含 token
- **内部通信签名**：Edge ↔ Cloud 指令使用 `EDGE_SYNC_SECRET` + HMAC-SHA256 + canonicalJson 签名，`createdAt` 60 秒内有效

## 项目结构

```
feishu-otp-server/
├── .env                         # 环境变量配置
├── package.json                 # Node.js 项目配置（依赖：pinyin-pro）
├── edge-functions/
│   ├── api/_shared.js           # 公共工具：签名 / KV / token / 地址解析 / 过期卡片（不映射路由）
│   ├── api/feishu_callback.js   # Edge 回调入口（路由 /api/feishu_callback）
│   └── api/expire.js            # Edge 接收 Cloud 过期指令并 PATCH 飞书（路由 /api/expire）
├── cloud-functions/
│   └── api/expiry.js            # Cloud 定时器：记录 + 到期向 Edge 发签名指令（路由 /api/expiry）
└── tests/
    ├── edge_feishu_callback.test.mjs
    ├── edge_expire.test.mjs
    └── cloud_expiry.test.mjs
```

## 核心模块说明

### edge-functions/api/_shared.js（公共工具）

- 签名：`canonicalJson`（递归按键名排序）、`signPayload` / `verifyPayload`（HMAC-SHA256，60 秒新鲜度）
- 地址解析：`resolveBase`（`EDGE_FUNCTION_BASE` / `CLOUD_FUNCTION_BASE` 优先，缺省请求同源）
- KV 直读直写、`getTenantAccessToken`（KV 缓存，仅在 Edge 内部使用）
- `buildExpiredCard` / `expireFeishuCard`（Edge 调飞书 PATCH 置卡片已失效）
- 统一响应 `json()`：`{code:0,data}` / `{code:1,message}`，错误带 `X-Edge-Error*` 头

### edge-functions/api/feishu_callback.js（Edge Function）

- 飞书回调协议：URL 验证、Token/签名校验、AES 解密、时效校验
- OTP 查询、私聊添加密钥、发送文本/卡片/管理通知
- 发送 OTP 卡片后，将 `{command:'schedule_expiry', message_id, renew_at, expire_at, user_id, key_name, createdAt}` 签名后 POST 到 Cloud `/api/expiry`（绝对时间戳，避免网络延时叠加）
- 管理群通知合并推送：获取时间=请求时刻，过期时间=续期后的最终过期时刻，推送次数=2
- 内置计时埋点：`[TIMING]` 日志输出校验、OTP 生成、卡片发送、转交、管理通知各阶段耗时

### cloud-functions/api/expiry.js（Cloud Function，仅定时器）

- 验签（`EDGE_SYNC_SECRET`）后**仅记录**需要延时更新的内容（`renew_at` / `expire_at` 绝对时间戳），立即返回 200
- 两个后台等待任务（等价 Python 等待线程）按时间戳触发，向 Edge `/api/expire` 发送签名指令：`renew_otp`（续期）、`expire_message`（过期）
- 全程不获取、不持有、不传输 tenant_access_token

### edge-functions/api/expire.js（Edge Function）

- 验签（`EDGE_SYNC_SECRET`，60 秒新鲜度）后调用飞书 `PATCH /im/v1/messages/{id}`：
  - `renew_otp`：重新生成当前窗口 OTP 并更新卡片（有效期内）
  - `expire_message`：将卡片更新为“已失效”

## 安装与配置

### 环境要求

- Node.js 18+（本地调试）
- 飞书开放平台账号与飞书应用
- EdgeOne Makers（EdgeOne CLI：`npm install -g edgeone`）

### 环境变量

```env
APP_ID=your_app_id
APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
# Cloud Function 调用 Edge Function 的域名（可选，缺省使用请求同源）
EDGE_FUNCTION_BASE=
# Edge Function 转发 Cloud Function 时的域名（可选，缺省使用请求同源）
CLOUD_FUNCTION_BASE=
# Edge 与 Cloud 内部通信签名密钥（HMAC-SHA256，两边必须一致）
EDGE_SYNC_SECRET=your_shared_secret
```

### 部署步骤

1. 安装依赖：`npm install`
2. 在 EdgeOne Makers 配置环境变量，并绑定 KV 命名空间（绑定变量 `KV_NAMESPACE` → 命名空间 `TOTP_SERVER`）
3. 确保 `EDGE_SYNC_SECRET` 在 Edge 与 Cloud 两侧配置相同的值
4. 在 KV 中添加密钥（也可由用户私聊命令添加）：`TOTP_SECRET`（默认）、`{大写拼音}_TOTP_SECRET`（具名）
5. 部署后飞书回调地址仍为 `https://[你的域名]/api/feishu_callback`（由 Edge Function 提供）
6. 本地调试：`npm run dev`；发布：推送到远端仓库自动构建

注意：Edge Function 中的 `pinyin-pro` 依赖走 npm（beta）打包，首次部署建议先用最小探针函数验证依赖可被构建。

### 本地测试

```bash
npm test
```

覆盖：Edge 回调（GET / URL 验证 / Token / 签名 / 时效 / TOTP / 拼音 / AES / OTP 全流程与签名转交 / 添加密钥 / 群聊拦截 / 加密模式）、Edge `/api/expire`（验签 / 过期签名 / 参数校验 / PATCH 已失效）、Cloud 定时器（验签 / 记录确认 / 到期签名指令 / 缺省同源）。

## 联系方式

如有问题或建议，欢迎通过 Gitee 平台反馈。
