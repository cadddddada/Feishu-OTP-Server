# Feishu OTP Server

提供给飞书企业应用的一次性密码（OTP）服务实现，运行在 EdgeOne Makers 上：**飞书业务全部由 Edge Function 处理，Cloud Function 仅作为过期更新定时器**。

## 架构与流程

```
飞书事件 ──► Edge Function /api/feishu_callback
                  │
                  ├─ 校验：URL 验证 / Token / 签名 / AES 解密 / 时效（2.0 事件从 header 取 token 与 event_type）
                  ├─ 分流：
                  │    ├─ im.message.receive_v1     消息：获取 OTP / 私聊添加密钥 / 帮助
                  │    ├─ application.bot.menu_v6   自定义菜单：事件 ID 即密钥标识符；ADD_TOTP 推送自助添加密钥卡片
                  │    └─ card.action.trigger       卡片回调：同步写 KV 并直接返回更新后的卡片
                  ├─ 发送文本 / TOTP 卡片 / 表单卡片 / 审计通知（fetch 调飞书）
                  ├─ 预生成下一窗口续期码 codeB，并取得飞书鉴权令牌（含有效期）
                  │
                  ├─ 发 TOTP 卡片后：AES-256-GCM 加密 + HMAC 签名转交 Cloud /api/expiry（模板代号 + 填充信息 + 目标时刻，携带 codeB 与令牌）
                  └─ 返回 200 给飞书（卡片回调返回 Toast + 卡片 JSON）

Cloud Function /api/expiry（定时 HTTP 发送器，直连飞书）
                  ├─ 验签通过后仅记录定时任务（模板代号 / 填充信息 / 目标时刻），立即返回 200
                  └─ 后台按绝对时间戳到期后，使用 Cloud 预编码模板直接调用飞书 PATCH：
                     renew_otp -> 更新为续期码（有效期内）；expire_message -> 置为已失效
                     （令牌临期时用环境凭据刷新）
```

## 主要功能

- **TOTP 生成与查询**：发送“xxxTOTP / xxxOTP / xxx验证码 / xxx密钥 / xxx动态码”获取动态密码，例如“阿里云TOTP”（兼容旧写法“阿里云OTP”）
- **密钥管理（私聊命令）**：`添加密钥 XXX <密钥/otpauth 链接>` 仅新增，标识符已存在则拒绝；`更新密钥 XXX <新密钥> <密码>` 仅更新；`删除密钥 XXX <密码>` 删除指定密钥。更新/删除需在环境变量中配置 `TOTP_ADMIN_PASSWORD`，未配置时一律禁止
- **自定义菜单事件**：机器人自定义菜单项的事件 ID 直接作为密钥标识符，点击即推送 TOTP 卡片（如事件 ID `YUNPAN` → 读取 `YUNPAN_TOTP_SECRET`）
- **菜单自助添加密钥**：事件 ID `ADD_TOTP` 触发表单卡片，用户填写标识符与密钥/otpauth 链接；后端中文转拼音、字母统一大写后写入 KV，并把结果卡片更新为“密钥名称 / 添加时间 / 添加人”三行（无“已保存”文案，标题即状态）；标识符已存在时拒绝写入，卡片标题变为“TOTP密钥未保存”并给出更新指引
- **密钥不缓存**：每次生成 OTP 都在 Edge 侧实时读取 KV（绑定变量 `KV_NAMESPACE`，命名空间 `TOTP_SERVER`）
- **卡片续期与过期更新**：首次密钥过期时 Cloud 定时触发 Edge 续期推送新密钥，再次过期后置为“已失效”
- **统一审计日志**：读取（获取 TOTP）/ 新建 / 更新 / 删除成功后向管理群 Webhook 推送“TOTP密钥审计日志”卡片，字段为操作人 / 操作类型 / 密钥名称 / 操作时间 /［过期时间］/ 操作来源；读取操作包含“过期时间”（续期后的最终过期时刻），失败或被拒绝的操作不推送
- **密钥回收站**：被覆盖 / 删除的旧密钥统一追加到 KV 的 `TOTP_RECYCLE_BIN`（单条 JSON 数组，字段 `key` / `value` / `deletedAt` / `operatorId` / `action`）；写入时懒清理超过 90 天的记录
- **tenant_access_token 不经过 API**：token 只在 Edge 内部获取、缓存与使用，Edge/Cloud 通信载荷中不含 token
- **内部通信加密与签名**：Edge → Cloud 敏感载荷（续期码 / 飞书令牌）AES-256-GCM 加密，外层 HMAC-SHA256 签名 + `createdAt` 60 秒时效

## 项目结构

```
feishu-otp-server/
├── .env                         # 环境变量配置
├── package.json                 # Node.js 项目配置（依赖：pinyin-pro）
├── edge-functions/
│   ├── api/_shared.js           # 公共工具：签名 / KV / token / 地址解析 / TOTP 卡片（不映射路由）
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

- 飞书回调协议：URL 验证、Token/签名校验、AES 解密、时效校验；2.0 事件统一从 `header` 读取 `event_type` / `token`（兼容 1.0 顶层字段）
- 事件分流：`im.message.receive_v1`（消息）、`application.bot.menu_v6`（自定义菜单）、`card.action.trigger`（卡片回调）
- OTP 查询、私聊添加密钥、发送文本/卡片/管理通知
- 菜单事件：`event_key` 经 `normalizeIdentifier` 规范化后作为密钥标识符，复用 TOTP 卡片流程；保留事件 ID `ADD_TOTP` 用于自助添加
- 卡片回调：同步处理（3 秒内响应），解析 `action.form_value` 写入 KV，响应体返回 `{toast, card:{type:'raw', data}}` 更新卡片；校验失败只返回错误 Toast（保留原卡片与已填内容）
- 标识符规范化 `normalizeIdentifier`：中文转拼音、英文字母大写、剔除空格与符号（`阿里云` / `ali yun` / `ali-yun` → `ALIYUN`）
- 密钥解析 `parseSecretInput`：支持纯 base32 密钥与 `otpauth://` 链接（取 `secret` 参数，标识符留空时回退到链接 label）
- 发送 TOTP 卡片后，将 `{command:'schedule_tasks', tasks:[{template, data, targetAt}]}` 签名后 POST 到 Cloud `/api/expiry`（任务携带预生成续期码与飞书鉴权令牌及有效期，绝对时间戳避免网络延时叠加）
- 统一审计通知：读取（获取 TOTP，操作类型=读取，含操作时间=请求时刻、过期时间=续期后的最终过期时刻）/ 新建 / 更新 / 删除成功后推送同一张审计卡片，操作来源区分“私聊命令 / 自定义菜单 / 菜单自助添加”

### cloud-functions/api/expiry.js（Cloud Function，定时 HTTP 发送器）

- 验签（`EDGE_SYNC_SECRET`）后**仅记录**定时任务（模板代号 + 填充信息 + 目标时刻），立即返回 200
- 内部预编码 `TEMPLATES`（`renew_otp` / `expire_message` → 直接 `PATCH` 飞书消息：续期码卡片 / 已失效卡片），后台等待任务（等价 Python 等待线程）按绝对时间戳到期后发送
- 接收 `{envelope, signature}`：先验签（含 `createdAt` 时效），再 AES-GCM 解密出任务内容
- 令牌由 Edge 随任务携带；缺失或临期时 Cloud 用环境凭据（`FEISHU_APP_ID` / `FEISHU_APP_SECRET`）刷新

## 系统调用流程（事件 → 响应）

所有飞书回调都进入同一个地址 `https://[域名]/api/feishu_callback`，先做统一校验，再按事件类型分流。

1. **统一校验**：GET 探活；`url_verification` 回显 challenge；Token 校验（2.0 事件取 `header.token`）；`x-lark-signature` 签名校验（`timestamp + nonce + FEISHU_ENCRYPT_KEY + body` 的 SHA-256）；配置 `FEISHU_ENCRYPT_KEY` 时对 `encrypt` 字段 AES-CBC 解密；消息时效校验。
2. **消息事件 `im.message.receive_v1`**：`添加密钥 XXX <密钥>` → 仅新增（已存在则拒绝）；`更新密钥 XXX <新密钥> <密码>` → 仅更新（不存在或密码错误则拒绝）；`删除密钥 XXX <密码>` → 删除（不存在或密码错误则拒绝）；`xxxTOTP / xxxOTP / xxx验证码 / xxx密钥 / xxx动态码` → 读 KV 生成 TOTP 卡片；其他 → 帮助文本。
3. **自定义菜单事件 `application.bot.menu_v6`**：`event_key` 即密钥标识符 → 复用 TOTP 卡片流程；`ADD_TOTP` → 推送自助添加密钥表单卡片。
4. **卡片回调 `card.action.trigger`**：同步处理表单提交（3 秒内响应），成功时返回 `{toast, card:{type:'raw', data}}` 并把结果卡片更新为“密钥名称 / 添加时间 / 添加人”三行；标识符已存在时不写入，卡片标题显示“TOTP密钥未保存”并给出更新指引；校验失败时只返回错误 Toast（审计通知经 `context.waitUntil` 异步发送，不占用 3 秒响应窗口）。
5. **统一审计**：读取（获取 TOTP）/ 新建 / 更新 / 删除成功后，向 `MANAGEMENT_WEBHOOK` 推送一张“TOTP密钥审计日志”卡片（操作人 / 操作类型 / 密钥名称 / 操作时间 /［过期时间，仅读取］/ 操作来源），失败或被拒绝的操作不推送。
6. **TOTP 卡片后续**：发卡后把续期/过期任务（预生成续期码 + 令牌 + 绝对时间戳）加密签名转交 Cloud `/api/expiry`，Cloud 到点直连飞书 PATCH 卡片。
7. 消息/菜单事件立即返回 200，业务逻辑由 `context.waitUntil` 异步执行；卡片回调必须同步返回，因此不走异步分支。

## OTP 密钥添加与管理路径

| 路径 | 入口 | 标识符处理 | 存储键 |
| --- | --- | --- | --- |
| 控制台手动 | EdgeOne KV 命名空间 `TOTP_SERVER` | 人工保证为大写字母/数字 | `TOTP_SECRET`（默认）或 `{标识符}_TOTP_SECRET` |
| 私聊命令 | “添加密钥 XXX <密钥/otpauth 链接>”（仅新增）、“更新密钥 XXX <新密钥> <密码>”（仅更新）、“删除密钥 XXX <密码>”（删除） | `normalizeIdentifier`（中文转拼音、字母大写、剔除空格与符号） | `{标识符}_TOTP_SECRET` |
| 菜单自助 | 自定义菜单 `ADD_TOTP` → 表单卡片 → 保存 | 同上；标识符留空时回退到 otpauth 链接的 label | `{标识符}_TOTP_SECRET` |

- 写入前校验 base32 可解码；`ADD_TOTP` 为系统保留标识符（规范化后为 `ADDTOTP`），不允许作为密钥名。
- 不覆盖：同名标识符的“添加密钥”与菜单自助添加都会被拒绝（提示改用“更新密钥”），只有“更新密钥”会覆盖已有值；菜单自助添加在标识符已存在时卡片标题显示“TOTP密钥未保存”。
- 更新/删除需操作密码：环境变量 `TOTP_ADMIN_PASSWORD`；未配置时不允许更新与删除，密码错误一律拒绝（常量时间比较）。
- 查询命令 `xxxTOTP`（兼容 `xxxOTP`）与菜单事件 ID 共用同一标识符空间。
- 回收站：被覆盖 / 删除的旧密钥追加到 KV `TOTP_RECYCLE_BIN`，字段 `key`（原始存储键）/ `value`（旧值）/ `deletedAt`（毫秒时间戳）/ `operatorId`（操作人 open_id）/ `action`（覆盖 / 删除）；每次写入前先清理超过 90 天的记录（懒处理），可在 KV 控制台直接查看或恢复。
- 密钥不入缓存，每次生成 OTP 都实时读取 KV。

## 安装与配置

### 环境要求

- Node.js 18+（本地调试）
- 飞书开放平台账号与飞书应用
- EdgeOne Makers（EdgeOne CLI：`npm install -g edgeone`）

### 环境变量

```env
FEISHU_APP_ID=your_app_id
FEISHU_APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
# 更新/删除密钥的操作密码（未配置时禁止更新与删除）
TOTP_ADMIN_PASSWORD=your_operation_password
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
4. 在 KV 中添加密钥（也可由用户私聊命令或菜单自助添加）：`TOTP_SECRET`（默认）、`{大写拼音}_TOTP_SECRET`（具名，如 `YUNPAN_TOTP_SECRET` 对应标识符 `YUNPAN`）
5. 飞书开放平台配置：
   - 事件订阅中添加 `im.message.receive_v1`（消息）与 `application.bot.menu_v6`（机器人自定义菜单）
   - 「事件与回调 → 回调配置」中启用卡片回调（`card.action.trigger`），回调地址与事件地址相同
   - 机器人自定义菜单中添加菜单项，动作选择“推送事件”，事件 ID 填密钥标识符（如 `YUNPAN`）或 `ADD_TOTP`（自助添加密钥）
6. 部署后飞书回调地址仍为 `https://[你的域名]/api/feishu_callback`（由 Edge Function 提供）
7. 本地调试：`npm run dev`；发布：推送到远端仓库自动构建

注意：Edge Function 中的 `pinyin-pro` 依赖走 npm（beta）打包，首次部署建议先用最小探针函数验证依赖可被构建。

### 本地测试

```bash
npm test
```

覆盖：Edge 回调（GET / URL 验证 / Token / 签名 / 时效 / TOTP / 拼音 / AES / OTP 全流程与签名转交 / 添加密钥 / 群聊拦截 / 加密模式 / 自定义菜单事件 / 卡片回调自助添加密钥）、Cloud 定时器（验签 / 记录确认 / 直连飞书续期与过期 PATCH / 令牌临期刷新）。

## 联系方式

如有问题或建议，欢迎通过 Gitee 平台反馈。
