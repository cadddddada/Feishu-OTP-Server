
import json
import base64
import hashlib
import hmac
import threading
import time
import os
import re
import requests
from http.server import BaseHTTPRequestHandler
from Crypto.Cipher import AES
import pyotp

# ==================== 配置 ====================
VERIFICATION_TOKEN = os.environ.get("FEISHU_VERIFICATION_TOKEN", "")
ENCRYPT_KEY = os.environ.get("FEISHU_ENCRYPT_KEY", "")
TOTP_SECRET = os.environ.get("TOTP_SECRET", "")
APP_ID = os.environ.get("FEISHU_APP_ID", "")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "")
MANAGEMENT_WEBHOOK = os.environ.get("MANAGEMENT_WEBHOOK", "")
KV_NAMESPACE = os.environ.get("KV_NAMESPACE", "OTP_KV")

try:
    from edgeone import kv as edgeone_kv
    kv = edgeone_kv
except ImportError:
    kv = None
    print("[WARN] EdgeOne KV not available, using mock")

# KV 操作（同上，省略重复）
def kv_get(key, default=None):
    if kv is None:
        return default
    try:
        raw = kv.get(key)
        return json.loads(raw) if raw else default
    except Exception as e:
        print(f"KV get error: {e}")
        return default

def kv_put(key, value, ttl=None):
    if kv is None:
        return
    try:
        kv.put(key, json.dumps(value), expiration_ttl=ttl)
    except Exception as e:
        print(f"KV put error: {e}")

def kv_delete(key):
    if kv is None:
        return
    try:
        kv.delete(key)
    except Exception as e:
        print(f"KV delete error: {e}")

# 获取 token（KV 缓存）
def get_tenant_access_token():
    cached = kv_get("tenant_access_token")
    now = int(time.time())
    if cached and now < cached.get("expire_at", 0) - 300:
        return cached["token"]
    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    resp = requests.post(url, json={"app_id": APP_ID, "app_secret": APP_SECRET}, timeout=10)
    data = resp.json()
    if data.get("code") != 0:
        raise Exception(f"获取 token 失败: {data.get('msg')}")
    token = data["tenant_access_token"]
    expire_at = now + data.get("expire", 7200)
    kv_put("tenant_access_token", {"token": token, "expire_at": expire_at}, ttl=7200)
    return token

# ==================== 消息发送与更新 ====================
def send_help(receive_id):
    token = get_tenant_access_token()
    url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "receive_id": receive_id,
        "msg_type": "text",
        "content": json.dumps({"text": "发送\u201COTP\u201D或\u201C密钥\u201D获取当前动态密码。"})
    }
    requests.post(url, headers=headers, json=payload, timeout=10)

def send_otp_card(receive_id, code, remaining_seconds, user_id):
    token = get_tenant_access_token()
    url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id"
    card = {
        "schema": "2.0",
        "config": {"update_multi": True},
        "body": {
            "direction": "vertical",
            "elements": [
                {
                    "tag": "column_set",
                    "flex_mode": "stretch",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [{
                        "tag": "column",
                        "width": "weighted",
                        "background_style": "blue-50",
                        "elements": [{
                            "tag": "markdown",
                            "content": f"## <font color='blue'>{code}</font>",
                            "text_align": "center"
                        }],
                        "padding": "16px 0px 16px 0px",
                        "vertical_spacing": "2px",
                        "horizontal_align": "left",
                        "vertical_align": "top",
                        "weight": 1
                    }],
                    "margin": "0px 0px 0px 0px"
                },
                {
                    "tag": "markdown",
                    "content": f"**<font color='orange'>剩余时间：{remaining_seconds}秒</font>**",
                    "text_align": "center",
                    "text_size": "normal",
                    "margin": "0px 0px 0px 0px",
                    "element_id": "remaining_time"
                },
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{
                                "tag": "markdown",
                                "content": "数据获取人：",
                                "text_align": "left",
                                "text_size": "heading",
                                "margin": "3px 0px 0px 0px"
                            }],
                            "padding": "0px 0px 0px 0px",
                            "direction": "vertical",
                            "horizontal_spacing": "8px",
                            "vertical_spacing": "8px",
                            "horizontal_align": "left",
                            "vertical_align": "top",
                            "margin": "0px 0px 0px 0px"
                        },
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{
                                "tag": "person",
                                "size": "medium",
                                "user_id": user_id,
                                "margin": "0px 0px 0px 0px"
                            }],
                            "vertical_align": "top"
                        }
                    ],
                    "margin": "0px 0px 0px 0px"
                }
            ]
        },
        "header": {
            "title": {"tag": "plain_text", "content": "OTP动态密钥"},
            "subtitle": {"tag": "plain_text", "content": ""},
            "text_tag_list": [{
                "tag": "text_tag",
                "text": {"tag": "plain_text", "content": "有效期内"},
                "color": "green"
            }],
            "template": "blue",
            "icon": {"tag": "standard_icon", "token": "lock"},
            "padding": "12px 8px 12px 8px"
        }
    }
    payload = {
        "receive_id": receive_id,
        "msg_type": "interactive",
        "content": json.dumps(card)
    }
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload, timeout=10)
    result = resp.json()
    if result.get("code") != 0:
        raise Exception(f"发送卡片失败: {result.get('msg')}")
    return result["data"]["message_id"]

def update_otp_card(message_id, user_id):
    token = get_tenant_access_token()
    url = f"https://open.feishu.cn/open-apis/im/v1/messages/{message_id}"
    card = {
        "schema": "2.0",
        "config": {"update_multi": True},
        "body": {
            "direction": "vertical",
            "elements": [
                {
                    "tag": "column_set",
                    "flex_mode": "stretch",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [{
                        "tag": "column",
                        "width": "weighted",
                        "background_style": "blue-50",
                        "elements": [{
                            "tag": "markdown",
                            "content": "## <font color='orange'>******</font>",
                            "text_align": "center"
                        }],
                        "padding": "16px 0px 16px 0px",
                        "vertical_spacing": "2px",
                        "horizontal_align": "left",
                        "vertical_align": "top",
                        "weight": 1
                    }],
                    "margin": "0px 0px 0px 0px"
                },
                {
                    "tag": "markdown",
                    "content": "**<font color='orange'>剩余时间：已过期</font>**",
                    "text_align": "center",
                    "text_size": "normal",
                    "margin": "0px 0px 0px 0px",
                    "element_id": "remaining_time"
                },
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{
                                "tag": "markdown",
                                "content": "数据获取人：",
                                "text_align": "left",
                                "text_size": "heading",
                                "margin": "3px 0px 0px 0px"
                            }],
                            "padding": "0px 0px 0px 0px",
                            "direction": "vertical",
                            "horizontal_spacing": "8px",
                            "vertical_spacing": "8px",
                            "horizontal_align": "left",
                            "vertical_align": "top",
                            "margin": "0px 0px 0px 0px"
                        },
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{
                                "tag": "person",
                                "size": "medium",
                                "user_id": user_id,
                                "margin": "0px 0px 0px 0px"
                            }],
                            "vertical_align": "top"
                        }
                    ],
                    "margin": "0px 0px 0px 0px"
                }
            ]
        },
        "header": {
            "title": {"tag": "plain_text", "content": "OTP动态密钥"},
            "subtitle": {"tag": "plain_text", "content": ""},
            "text_tag_list": [{
                "tag": "text_tag",
                "text": {"tag": "plain_text", "content": "已失效"},
                "color": "red"
            }],
            "template": "blue",
            "icon": {"tag": "standard_icon", "token": "lock"},
            "padding": "12px 8px 12px 8px"
        }
    }
    payload = {"content": json.dumps(card)}
    resp = requests.patch(url, headers={"Authorization": f"Bearer {token}"}, json=payload, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"更新卡片失败: {resp.text}")
    return resp.json()

def send_management_card(user_id, request_time, expire_time_str):
    """发送管理群卡片通知"""
    if not MANAGEMENT_WEBHOOK:
        return
    card = {
        "schema": "2.0",
        "config": {"update_multi": True},
        "body": {
            "direction": "vertical",
            "elements": [
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "115px",
                            "elements": [{"tag": "markdown", "content": "数据获取人：", "text_align": "left", "text_size": "heading", "margin": "3px 0px 0px 0px"}],
                            "padding": "0px 0px 0px 0px",
                            "direction": "vertical",
                            "horizontal_spacing": "8px",
                            "vertical_spacing": "8px",
                            "horizontal_align": "left",
                            "vertical_align": "top",
                            "margin": "0px 0px 0px 0px"
                        },
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{"tag": "person", "size": "medium", "user_id": user_id, "margin": "0px 0px 0px 0px"}],
                            "vertical_align": "top"
                        }
                    ],
                    "margin": "0px 0px 0px 0px"
                },
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "115px",
                            "elements": [{"tag": "markdown", "content": "获取时间：", "text_align": "left", "text_size": "heading", "margin": "0px 0px 0px 0px"}],
                            "padding": "0px 0px 0px 0px",
                            "direction": "vertical",
                            "horizontal_spacing": "8px",
                            "vertical_spacing": "8px",
                            "horizontal_align": "left",
                            "vertical_align": "top",
                            "margin": "0px 0px 0px 0px"
                        },
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{"tag": "markdown", "content": request_time, "text_align": "left", "text_size": "normal", "margin": "2px 0px 0px 0px"}],
                            "vertical_align": "top"
                        }
                    ],
                    "margin": "0px 0px 0px 0px"
                },
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "horizontal_align": "left",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "115px",
                            "elements": [{"tag": "markdown", "content": "密钥过期时间：", "text_align": "left", "text_size": "heading", "margin": "0px 0px 0px 0px"}],
                            "padding": "0px 0px 0px 0px",
                            "direction": "vertical",
                            "horizontal_spacing": "8px",
                            "vertical_spacing": "8px",
                            "horizontal_align": "left",
                            "vertical_align": "top",
                            "margin": "0px 0px 0px 0px"
                        },
                        {
                            "tag": "column",
                            "width": "auto",
                            "elements": [{"tag": "markdown", "content": expire_time_str, "text_align": "left", "text_size": "normal", "margin": "2px 0px 0px 0px"}],
                            "vertical_align": "top"
                        }
                    ],
                    "margin": "0px 0px 0px 0px"
                }
            ]
        },
        "header": {
            "title": {"tag": "plain_text", "content": "OTP动态密钥获取日志"},
            "subtitle": {"tag": "plain_text", "content": ""},
            "template": "blue",
            "icon": {"tag": "standard_icon", "token": "lock"},
            "padding": "12px 8px 12px 8px"
        }
    }
    payload = {"msg_type": "interactive", "card": card}
    requests.post(MANAGEMENT_WEBHOOK, json=payload, timeout=5)

# ==================== OTP 生成 ====================
def generate_otp():
    totp = pyotp.TOTP(os.environ.get("TOTP_SECRET", ""))
    code = totp.now()
    remaining = totp.interval - (time.time() % totp.interval)
    expire_ts = int(time.time() + remaining)
    return code, expire_ts

# ==================== AES 解密 ====================
class AESCipher:
    def __init__(self, key: str):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        self.block_size = 16

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def decrypt(self, encrypted: bytes) -> bytes:
        from Crypto.Cipher import AES
        iv = encrypted[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(encrypted[self.block_size:]))

    def decrypt_string(self, encrypted_b64: str) -> str:
        encrypted = base64.b64decode(encrypted_b64)
        return self.decrypt(encrypted).decode('utf-8')


# ==================== Handler ====================
class handler(BaseHTTPRequestHandler):
    """飞书事件回调处理"""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode('utf-8'))

    def do_POST(self):
        print(f"[DEBUG] ==== 收到 POST 请求 ====")
        print(f"[DEBUG] 请求路径: {self.path}")
        print(f"[DEBUG] 请求头: {dict(self.headers)}")

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')

            try:
                data = json.loads(body)
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON 解析失败: {e}")
                self._send_error(400, "Invalid JSON")
                return

            print(f"[DEBUG] 是否包含 encrypt 字段: {'encrypt' in data}")

            # 处理加密
            if ENCRYPT_KEY and 'encrypt' in data:
                print("[DEBUG] 进入加密模式处理")
                try:
                    cipher = AESCipher(ENCRYPT_KEY)
                    decrypted_str = cipher.decrypt_string(data['encrypt'])
                    event_data = json.loads(decrypted_str)
                    print(f"[DEBUG] 解密成功，事件数据: {json.dumps(event_data)}")

                    if event_data.get('schema') == '2.0':
                        header = event_data.get('header', {})
                        event_data['type'] = header.get('event_type')
                        event_data['token'] = header.get('token')

                except Exception as e:
                    print(f"[ERROR] 解密失败: {e}")
                    self._send_error(500, f"Decryption failed: {str(e)}")
                    return
            else:
                print("[DEBUG] 明文模式处理")
                event_data = data

            # Token 验证
            if not self._verify_token(event_data):
                print("[ERROR] Token 验证失败，返回 403")
                self._send_error(403, "Token mismatch")
                return
            print("[DEBUG] Token 验证通过")

            # 处理 URL 验证
            if event_data.get('type') == 'url_verification':
                challenge = event_data.get('challenge')
                print(f"[DEBUG] URL验证，challenge: {challenge}")
                if challenge:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"challenge": challenge}).encode('utf-8'))
                else:
                    self._send_error(400, "Missing challenge")
                return

            # 签名校验（非 URL 验证时）
            if not self._verify_signature(body):
                print("[ERROR] 签名校验失败，返回 403")
                self._send_error(403, "Signature verification failed")
                return
            print("[DEBUG] 签名校验通过")

            # 消息时效性检测
            if not self._check_message_timeliness(event_data):
                print("[WARN] 消息已过期或来自未来，丢弃")
                self._send_error(400, "Message expired")
                return

            # 立即返回 200，异步处理业务逻辑
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"code": 0, "msg": "success"}).encode('utf-8'))
            print("[DEBUG] 已返回 200，启动异步事件处理")

            threading.Thread(target=self._handle_event, args=(event_data,), daemon=True).start()

        except Exception as e:
            print(f"[ERROR] 处理请求异常: {e}")
            self._send_error(500, str(e))

    def _verify_token(self, data):
        """验证 Verification Token"""
        token = data.get('token', '')
        print(f"[DEBUG] 事件中的 token: {token[:10]}...")
        print(f"[DEBUG] 配置的 token: {VERIFICATION_TOKEN[:10]}...")
        result = hmac.compare_digest(token, VERIFICATION_TOKEN)
        print(f"[DEBUG] Token 比对结果: {result}")
        return result

    def _check_message_timeliness(self, event_data):
        """检查消息时效性，创建时间超过30秒或为未来时间则视为无效"""
        event = event_data.get('event', {})
        message = event.get('message', {})
        create_time_str = message.get('create_time', '')
        if not create_time_str:
            create_time_str = event_data.get('create_time', '')
        if not create_time_str:
            print("[DEBUG] 未找到 create_time 字段，跳过时效检测")
            return True
        try:
            create_time_ms = int(create_time_str)
            create_time_s = create_time_ms / 1000.0
            now_s = time.time()
            diff = now_s - create_time_s
            print(f"[DEBUG] 消息创建时间: {create_time_str}, 时间差: {diff:.1f}秒")
            if diff < -5:
                print(f"[WARN] 消息来自未来（{diff:.0f}秒后），丢弃")
                return False
            if diff > 30:
                print(f"[WARN] 消息已过期（{diff:.0f}秒前），丢弃")
                return False
            return True
        except (ValueError, TypeError) as e:
            print(f"[WARN] create_time 解析失败: {e}")
            return True

    def _verify_signature(self, body):
        """飞书签名校验"""
        timestamp = self.headers.get('X-Lark-Request-Timestamp', '')
        nonce = self.headers.get('X-Lark-Request-Nonce', '')
        signature = self.headers.get('X-Lark-Signature', '')
        if not timestamp or not nonce or not signature:
            print("[DEBUG] 缺少签名请求头")
            return False
        sign_str = timestamp + nonce + ENCRYPT_KEY + body
        computed = hashlib.sha256(sign_str.encode()).hexdigest()
        return hmac.compare_digest(computed, signature)

    def _handle_event(self, event_data):
        """处理业务事件（异步执行）"""
        event_type = event_data.get('type')
        print(f"[DEBUG] 处理事件类型: {event_type}")
        if event_type == 'im.message.receive_v1':
            self._handle_message_event(event_data)
        else:
            print(f"[INFO] 忽略未处理的事件类型: {event_type}")

    def _handle_message_event(self, event_data):
        try:
            event = event_data.get('event', {})
            message = event.get('message', {})
            content_str = message.get('content', '{}')
            if not content_str or content_str == '{}':
                content_str = event.get('content', '{}')

            try:
                content_json = json.loads(content_str)
                text = content_json.get('text', '')
            except:
                text = ''

            # 获取发送者信息（兼容多种格式）
            sender = event.get('sender', {})
            sender_id = sender.get('sender_id', {})
            user_id = sender_id.get('open_id') or sender_id.get('user_id') or sender.get('open_id')
            if not user_id:
                print("[ERROR] 无法获取用户ID")
                return

            # 检测是否包含关键词
            if re.search(r'(OTP|密钥|验证码|动态码)', text, re.IGNORECASE):
                code, expire_ts = generate_otp()
                expire_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_ts))
                remaining_seconds = max(1, int(expire_ts - time.time()))

                message_id = send_otp_card(user_id, code, remaining_seconds, user_id)
                self._schedule_expiry_update(message_id, remaining_seconds, user_id)

                request_time_str = time.strftime('%Y-%m-%d %H:%M:%S')
                send_management_card(user_id, request_time_str, expire_time_str)
            else:
                send_help(user_id)

        except Exception as e:
            print(f"处理消息事件出错: {e}")

    def _schedule_expiry_update(self, message_id, delay_seconds, user_id):
        """启动异步线程，延迟更新 OTP 卡片状态为已过期"""
        def _update_expired():
            time.sleep(delay_seconds)
            try:
                update_otp_card(message_id, user_id)
                print(f"[INFO] OTP 卡片 {message_id} 已过期，状态已更新")
            except Exception as err:
                print(f"[ERROR] 更新 OTP 卡片失败: {err}")

        t = threading.Thread(target=_update_expired, daemon=True)
        t.start()

    def _send_error(self, code, message):
        print(f"[ERROR] 返回错误 {code}: {message}")
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"code": code, "msg": message}).encode('utf-8'))

    def log_message(self, format, *args):
        pass
