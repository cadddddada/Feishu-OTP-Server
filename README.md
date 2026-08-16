# Feishu OTP Server

提供给飞书企业应用的一次性密码（OTP）服务实现，运行在 EdgeOne Makers 上：**飞书业务全部由 Edge Function 处理，Cloud Function 仅作为过期更新定时器**。

## 架构与流程

```
飞书事件 ──► Edge Function /api/feishu_callback
                  │
                  ├─ 校验：URL 验证 / Token / 签名 / AES 解密 / 时效
                  ├─ 处理消息：获取 OTP（KV 直读 + TOTP）、私聊添加/更新密钥
                   ├─ 发送文本 / OTP 卡片 / 管理群通知（fetch 调飞书）
                   ├─ 预生成下一窗口续期码 codeB，并取得飞书鉴权令牌（含有效期）
                   │
                   ├─ 发卡片后：AES-256-GCM 加密 + HMAC 签名转交 Cloud /api/expiry（模板代号 + 填充信息 + 目标时刻，携带 codeB 与令牌）
                   └─ 返回 200 给飞书

Cloud Function /api/expiry（定时 HTTP 发送器，直连飞书）
                   ├─ 验签通过后仅记录定时任务（模板代号 / 填充信息 / 目标时刻），立即返回 200
                   └─ 后台按绝对时间戳到期后，使用 Cloud 预编码模板直接调用飞书 PATCH：
                      renew_otp -> 更新为续期码（有效期内）；expire_message -> 置为已失效
                      （令牌临期时用环境凭据刷新）
```

## 主要功能

- **OTP 生成与查询**：发送“xxxOTP / xxx验证码 / xxx密钥 / xxx动态码”获取动态密码，例如“阿里云OTP”
- **密钥自助添加/更新**：私聊发送“添加密钥 XXX <密钥>”写入/更新 KV，例如“添加密钥 阿里云 JBSWY3DPEHPK3PXP”
- **密钥不缓存**：每次生成 OTP 都在 Edge 侧实时读取 KV（绑定变量 `KV_NAMESPACE`，命名空间 `TOTP_SERVER`）
- **卡片续期与过期更新**：首次密钥过期时 Cloud 定时触发 Edge 续期推送新密钥，再次过期后置为“已失效”
- **合并管理通知**：一次请求累计推送 2 次 OTP（含续期），管理群卡片合并为一条（获取时间 / 最终过期时间 / 推送次数）
- **tenant_access_token 不经过 API**：token 只在 Edge 内部获取、缓存与使用，Edge/Cloud 通信载荷中不含 token
- **内部通信加密与签名**：Edge → Cloud 敏感载荷（续期码 / 飞书令牌）AES-256-GCM 加密，外层 HMAC-SHA256 签名 + `createdAt` 60 秒时效

## 项目结构

```
feishu-otp-server/
├── .env                         # 环境变量配置
├── package.json                 # Node.js 项目配置（依赖：pinyin-pro）
├── edge-functions/
│   ├── api/_shared.js           # 公共工具：签名 / KV / token / 地址解析 / OTP 卡片（不映射路由）
│   ├── api/feishu_callback.js   # Edge 回调入口（路由 /api/feishu_callback）
├── cloud-functions/
│   └── api/expiry.js            # Cloud 定时 HTTP 发送器：记录 + 到期直连飞书 PATCH（路由 /api/expiry）
└── tests/
    ├── edge_feishu_callback.test.mjs
    └── cloud_expiry.test.mjs
```

## 核心模块说明

### edge-functions/api/_shared.js（公共工具）

- 签名：`canonicalJson`（递归按键名排序）、`signPayload` / `verifyPayload`（HMAC-SHA256，60 秒新鲜度）
- 敏感载荷加密：`encryptPayload` / `decryptPayload`（AES-256-GCM，密钥由 `EDGE_SYNC_SECRET` 派生）
- 地址解析：`resolveBase`（`EDGE_FUNCTION_BASE` / `CLOUD_FUNCTION_BASE` 优先，缺省请求同源）
- KV 直读直写、`getTenantAccessToken`（KV 缓存，仅在 Edge 内部使用）
- `generateNewOtp` 预生成下一窗口 OTP（返回 `nextCode`）；`getTenantAccessToken` 返回 `{token, expireAt}`
- 统一响应 `json()`：`{code:0,data}` / `{code:1,message}`，错误带 `X-Edge-Error*` 头

### edge-functions/api/feishu_callback.js（Edge Function）

- 飞书回调协议：URL 验证、Token/签名校验、AES 解密、时效校验
- OTP 查询、私聊添加密钥、发送文本/卡片/管理通知
- 发送 OTP 卡片后，将 `{command:'schedule_tasks', tasks:[{template, data, targetAt}]}` 签名后 POST 到 Cloud `/api/expiry`（任务携带预生成续期码与飞书鉴权令牌及有效期，绝对时间戳避免网络延时叠加）
- 管理群通知合并推送：获取时间=请求时刻，过期时间=续期后的最终过期时刻，推送次数=2

### cloud-functions/api/expiry.js（Cloud Function，定时 HTTP 发送器）

- 验签（`EDGE_SYNC_SECRET`）后**仅记录**定时任务（模板代号 + 填充信息 + 目标时刻），立即返回 200
- 内部预编码 `TEMPLATES`（`renew_otp` / `expire_message` → 直接 `PATCH` 飞书消息：续期码卡片 / 已失效卡片），后台等待任务（等价 Python 等待线程）按绝对时间戳到期后发送
- 接收 `{envelope, signature}`：先验签（含 `createdAt` 时效），再 AES-GCM 解密出任务内容
- 令牌由 Edge 随任务携带；缺失或临期时 Cloud 用环境凭据（`FEISHU_APP_ID` / `FEISHU_APP_SECRET`）刷新

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

覆盖：Edge 回调（GET / URL 验证 / Token / 签名 / 时效 / TOTP / 拼音 / AES / OTP 全流程与签名转交 / 添加密钥 / 群聊拦截 / 加密模式）、Cloud 定时器（验签 / 记录确认 / 直连飞书续期与过期 PATCH / 令牌临期刷新）。

## 联系方式

如有问题或建议，欢迎通过 Gitee 平台反馈。
