

# Feishu OTP Server

基于飞书（Feishu/Lark）的一次性密码（OTP）服务实现。

## 项目简介

本项目是一个飞书云函数实现的 OTP（一次性密码）服务器，用于生成和验证一次性密码，并通过飞书消息卡片与用户进行交互。主要应用于双因素认证场景。

## 主要功能

- **OTP 生成与验证**：生成安全的一次性密码并通过飞书发送
- **飞书消息卡片**：使用交互式卡片展示 OTP 及相关信息
- **AES 加密**：实现 AES 加密算法用于飞书 API 通信安全
- **事件处理**：支持飞书平台的事件回调和消息处理
- **签名验证**：验证请求来源的真实性和完整性
- **消息时效性检查**：确保消息处理的时效性要求

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

#### KV 存储操作
- `kv_get(key, default=None)`：获取键值
- `kv_put(key, value, ttl=None)`：存储键值（支持过期时间）
- `kv_delete(key)`：删除键值

#### OTP 相关功能
- `generate_otp()`：生成一次性密码
- `send_otp_card(receive_id, code, remaining_seconds, user_id)`：发送 OTP 卡片消息
- `update_otp_card(message_id, user_id)`：更新 OTP 卡片
- `send_help(receive_id)`：发送帮助信息
- `send_management_card(user_id, request_time, expire_time_str)`：发送管理卡片

#### 飞书 API 集成
- `get_tenant_access_token()`：获取飞书租户访问令牌

#### 安全模块
- `AESCipher` 类：AES 加解密工具，用于飞书 API 通信加密
  - `__init__(key: str)`：初始化加密器
  - `decrypt(encrypted: bytes)`：解密数据
  - `decrypt_string(encrypted_b64: str)`：解密 Base64 编码的字符串

#### HTTP 处理器
- `handler` 类：继承自 `BaseHTTPRequestHandler`，处理 HTTP 请求
  - `do_GET()`：处理 GET 请求
  - `do_POST()`：处理 POST 请求
  - `_verify_token(token)`：验证请求令牌
  - `_verify_signature(body)`：验证请求签名
  - `_check_message_timeliness(event_data)`：检查消息时效性
  - `_handle_event(event_data)`：处理飞书事件
  - `_handle_message_event(event_data)`：处理消息事件

## 安装与配置

### 环境要求

- Python 3.8+
- 飞书开放平台账号
- 飞书应用（已配置云函数）

### 安装步骤

1. 克隆项目：
```bash
git clone <repository-url>
cd feishu-otp-server
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 配置环境变量（`.env` 文件）：
```env
# 飞书应用配置
APP_ID=your_app_id
APP_SECRET=your_app_secret
ENCRYPT_KEY=your_encrypt_key

# 其他配置
...
```

### 飞书平台配置

1. 在[飞书开放平台](https://open.feishu.cn/)创建应用
2. 配置云函数触发器
3. 设置事件订阅权限
4. 配置应用凭证（App ID 和 App Secret）

## 使用方法

### 部署到飞书云函数

1. 将项目部署到飞书云函数环境
2. 配置云函数触发器（HTTP 触发）
3. 设置事件订阅 URL 为云函数地址

### API 接口

#### 接收飞书事件
- **URL**：云函数触发器 URL
- **方法**：GET（验证 URL 有效性）、POST（接收事件）

#### 典型事件类型
- `im.message.message_v1`：新消息事件
- `im.message.message_read_v1`：消息已读事件
- 自定义应用事件

## 安全机制

1. **令牌验证**：使用飞书提供的验证令牌确认请求来源
2. **签名验证**：使用 HMAC-SHA256 验证请求签名
3. **消息时效性**：检查消息时间戳，防止重放攻击
4. **AES 加密**：敏感数据使用 AES 加密传输

## 依赖说明

主要依赖包括：
- `requests` 或其他 HTTP 库（用于飞书 API 调用）
- 标准库模块：`hmac`, `hashlib`, `base64`, `json`, `time`, `urllib` 等

详细依赖请查看 `requirements.txt` 文件。

## 开发参考

### 飞书开放平台文档
- [飞书开放平台官方文档](https://open.feishu.cn/document/)
- [云函数开发指南](https://open.feishu.cn/document/server-docs/cloud-functions/intro)
- [消息卡片文档](https://open.feishu.cn/document/message-cards/intro)

### 相关资源
- 项目仓库：[feishu-otp-server](https://gitee.com/a6283263/feishu-otp-server)

## 许可证

本项目遵循相应的开源许可证协议。

## 贡献指南

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature`
3. 提交更改：`git commit -m 'Add some feature'`
4. 推送分支：`git push origin feature/your-feature`
5. 提交 Pull Request

## 联系方式

如有问题或建议，欢迎通过 Gitee 平台反馈。