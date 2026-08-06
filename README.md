

# Feishu OTP Server

提供给飞书企业应用的一次性密码（OTP）服务实现。

## 项目简介

本项目是EdgeOne Maker实现的 OTP（一次性密码）服务器，用于生成和验证一次性密码，并通过飞书消息卡片与用户进行交互。主要应用于双因素认证场景。

## 主要功能

- **OTP 生成与验证**：生成安全的一次性密码并通过飞书发送
- **密钥自助添加/更新**：私聊发送“添加密钥 XXX <密钥>”即可写入/更新 KV 中的密钥，例如“添加密钥 阿里云 JBSWY3DPEHPK3PXP”
- **飞书消息卡片**：使用交互式卡片展示 OTP 及相关信息
- **事件处理**：支持飞书平台的事件回调和消息处理

## 项目结构

```
feishu-otp-server/
├── .env                    # 环境变量配置
├── .gitignore              # Git 忽略文件配置
├── cloud-functions/
│   └── api/
│       └── feishu_callback.py    # 核心业务逻辑
├── pyproject.toml          # Python 项目配置
├── requirements.txt        # Python 依赖
└── uv.lock                 # 依赖锁定文件
```

## 核心模块说明

### feishu_callback.py

这是项目的主入口文件，包含以下核心组件：

#### KV 存储操作（通过 Edge Function KV 代理）
Python 云函数不支持直接访问 KV，以下操作通过 HTTP 调用 Edge Function 代理（`/api/kv`）实时读写，不缓存：
- `kv_get(key, default=None)`：获取键值
- `kv_put(key, value, ttl=None)`：存储键值（代理暂不支持 TTL）
- `kv_delete(key)`：删除键值

#### OTP 相关功能
- `generate_otp()`：生成一次性密码
- `send_otp_card(receive_id, code, remaining_seconds, user_id)`：发送 OTP 卡片消息
- `update_otp_card(message_id, user_id)`：更新 OTP 卡片
- `send_help(receive_id)`：发送帮助信息
- `send_management_card(user_id, request_time, expire_time_str)`：发送管理卡片


## 安装与配置

### 环境要求

- Python 3.8+
- 飞书开放平台账号
- 飞书应用
- EdgeOne Maker

### 安装步骤

1. 使用EdgeOne Makesr克隆项目

2. 飞书开放平台创建企业应用：
- 配置机器人能力
- 开通以下权限：
 - `im:message`
 - `im:message.p2p_msg:readonly`
 - `im:message:update`
- 配置事件与回调
 - 加密策略中配置`Encrypt Key`与`Verification Token`

3. 在EdgeOne Makers中配置环境变量，并绑定 KV 命名空间：
```env
APP_ID=your_app_id
APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
# KV_PROXY_URL 可选，留空时自动从回调请求的 Eo-Pages-Host 头推导出 https://{域名}/api/kv
KV_PROXY_TOKEN=与边缘函数一致的自定义令牌
```

4. 部署 KV 代理 Edge Function（`edge-functions/api/kv/index.js`，路由 `/api/kv`）：
 - Edge Function 通过绑定的 `KV_NAMESPACE`（命名空间 `TOTP_SERVER`）读写 KV
 - 在项目中配置环境变量 `KV_PROXY_TOKEN`，边缘函数与 Python 云函数使用同一个值
 - 代理地址由 Python 云函数从每次回调请求的 `Eo-Pages-Host` 头自动推导（`https://{域名}/api/kv`），无需手动配置域名

5. 在 KV 命名空间 `TOTP_SERVER` 中添加 OTP 密钥（密钥不缓存，每次生成动态验证码时都会从 KV 读取）：
 - 默认密钥：键名 `TOTP_SECRET`，值为 base32 格式的 TOTP 密钥
 - 具名密钥：键名 `{大写拼音}_TOTP_SECRET`，例如用户发送“阿里云OTP”时读取 `ALIYUN_TOTP_SECRET`

6. 配置Makers容器的域名等基础信息

7. 将回调地址`https://[你的域名]/api/feishu_callback`填入事件请求地址，连接模式选择 将事件发送至开发者服务器

## 联系方式

如有问题或建议，欢迎通过 Gitee 平台反馈。
