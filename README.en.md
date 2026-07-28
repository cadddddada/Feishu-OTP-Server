# Feishu OTP Server

Implementation of a One-Time Password (OTP) service based on Feishu (Lark).

## Project Introduction

This project is an OTP (One-Time Password) server implemented using Feishu Cloud Functions, designed to generate and verify one-time passwords and interact with users via Feishu message cards. It is primarily applied in two-factor authentication scenarios.

## Main Features

- **OTP Generation and Verification**: Generate secure one-time passwords and send them via Feishu.
- **Feishu Message Cards**: Display OTP and related information using interactive cards.
- **AES Encryption**: Implement AES encryption algorithms for secure Feishu API communication.
- **Event Handling**: Support for Feishu platform event callbacks and message processing.
- **Signature Verification**: Verify the authenticity and integrity of request sources.
- **Message Timeliness Check**: Ensure message processing meets timeliness requirements.

## Project Structure

```
feishu-otp-server/
├── .env                    # Environment variable configuration
├── .gitignore              # Git ignore file configuration
├── cloud-functions/
│   └── api/
│       └── feishu_callback.py    # Core business logic
├── pyproject.toml          # Python project configuration
├── requirements.txt        # Python dependencies
└── uv.lock                 # Dependency lock file
```

## Core Module Description

### feishu_callback.py

This is the main entry point file for the project, containing the following core components:

#### KV Storage Operations
- `kv_get(key, default=None)`: Get key-value pairs.
- `kv_put(key, value, ttl=None)`: Store key-value pairs (supports expiration time).
- `kv_delete(key)`: Delete key-value pairs.

#### OTP Related Functions
- `generate_otp()`: Generate a one-time password.
- `send_otp_card(receive_id, code, remaining_seconds, user_id)`: Send OTP card message.
- `update_otp_card(message_id, user_id)`: Update OTP card.
- `send_help(receive_id)`: Send help information.
- `send_management_card(user_id, request_time, expire_time_str)`: Send management card.

#### Feishu API Integration
- `get_tenant_access_token()`: Get Feishu tenant access token.

#### Security Module
- `AESCipher` Class: AES encryption/decryption tool, used for Feishu API communication encryption.
  - `__init__(key: str)`: Initialize the cipher.
  - `decrypt(encrypted: bytes)`: Decrypt data.
  - `decrypt_string(encrypted_b64: str)`: Decrypt Base64 encoded string.

#### HTTP Handler
- `handler` Class: Inherits from `BaseHTTPRequestHandler`, handles HTTP requests.
  - `do_GET()`: Handle GET requests.
  - `do_POST()`: Handle POST requests.
  - `_verify_token(token)`: Verify request token.
  - `_verify_signature(body)`: Verify request signature.
  - `_check_message_timeliness(event_data)`: Check message timeliness.
  - `_handle_event(event_data)`: Handle Feishu events.
  - `_handle_message_event(event_data)`: Handle message events.

## Installation & Configuration

### Environment Requirements

- Python 3.8+
- Feishu Open Platform Account
- Feishu Application (Cloud Function configured)

### Installation Steps

1. Clone the project:
```bash
git clone <repository-url>
cd feishu-otp-server
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables (`.env` file):
```env
# Feishu App Configuration
APP_ID=your_app_id
APP_SECRET=your_app_secret
ENCRYPT_KEY=your_encrypt_key

# Other Configuration
...
```

### Feishu Platform Configuration

1. Create an application on the [Feishu Open Platform](https://open.feishu.cn/)
2. Configure Cloud Function triggers
3. Set event subscription permissions
4. Configure application credentials (App ID and App Secret)

## Usage Methods

### Deploy to Feishu Cloud Function

1. Deploy the project to the Feishu Cloud Function environment.
2. Configure Cloud Function triggers (HTTP trigger).
3. Set the event subscription URL to the Cloud Function address.

### API Interfaces

#### Receive Feishu Events
- **URL**: Cloud Function Trigger URL
- **Method**: GET (Verify URL validity), POST (Receive events)

#### Typical Event Types
- `im.message.message_v1`: New message event
- `im.message.message_read_v1`: Message read event
- Custom application events

## Security Mechanisms

1. **Token Verification**: Use the verification token provided by Feishu to confirm the request source.
2. **Signature Verification**: Use HMAC-SHA256 to verify request signatures.
3. **Message Timeliness**: Check message timestamps to prevent replay attacks.
4. **AES Encryption**: Sensitive data is transmitted using AES encryption.

## Dependencies

Main dependencies include:
- `requests` or other HTTP libraries (for Feishu API calls)
- Standard library modules: `hmac`, `hashlib`, `base64`, `json`, `time`, `urllib`, etc.

Please refer to the `requirements.txt` file for detailed dependencies.

## Development Reference

### Feishu Open Platform Documentation
- [Feishu Open Platform Official Documentation](https://open.feishu.cn/document/)
- [Cloud Function Development Guide](https://open.feishu.cn/document/server-docs/cloud-functions/intro)
- [Message Cards Documentation](https://open.feishu.cn/document/message-cards/intro)

### Related Resources
- Project Repository: [feishu-otp-server](https://gitee.com/a6283263/feishu-otp-server)

## License

This project follows the corresponding open-source license agreement.

## Contribution Guidelines

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'Add some feature'`
4. Push the branch: `git push origin feature/your-feature`
5. Submit a Pull Request

## Contact Information

If you have any questions or suggestions, please feel free to provide feedback through the Gitee platform.