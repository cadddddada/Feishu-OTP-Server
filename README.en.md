# Feishu OTP Server

Provides an One-Time Password (OTP) service implementation for Feishu enterprise applications.

## Project Overview

This project is an OTP (One-Time Password) server built with EdgeOne Maker. It generates and verifies one-time passwords and interacts with users through Feishu message cards. It is primarily used in two-factor authentication scenarios.

## Key Features

- **OTP Generation and Verification**: Generates secure one-time passwords and sends them via Feishu
- **Feishu Message Cards**: Displays OTP and related information using interactive cards
- **Event Handling**: Supports event callbacks and message processing from the Feishu platform

## Project Structure

```
feishu-otp-server/
├── .env                    # Environment variables configuration
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

This is the main entry file of the project, containing the following core components:

#### KV Storage Operations
- `kv_get(key, default=None)`: Get key value
- `kv_put(key, value, ttl=None)`: Store key value (supports expiration time)
- `kv_delete(key)`: Delete key value

#### OTP Related Functions
- `generate_otp()`: Generate a one-time password
- `send_otp_card(receive_id, code, remaining_seconds, user_id)`: Send OTP card message
- `update_otp_card(message_id, user_id)`: Update OTP card
- `send_help(receive_id)`: Send help information
- `send_management_card(user_id, request_time, expire_time_str)`: Send management card

## Installation and Configuration

### Requirements

- Python 3.8+
- Feishu open platform account
- Feishu application
- EdgeOne Maker

### Installation Steps

1. Clone the project using EdgeOne Maker

2. Create an enterprise application on the Feishu open platform:
   - Configure bot capabilities
   - Enable the following permissions:
     - `im:message`
     - `im:message.p2p_msg:readonly`
     - `im:message:update`
   - Configure events and callbacks
   - Configure `Encrypt Key` and `Verification Token` in the encryption settings

3. Configure environment variables in EdgeOne Maker and bind the KV namespace:
```env
APP_ID=your_app_id
APP_SECRET=your_app_secret
FEISHU_VERIFICATION_TOKEN=your_verification_token
FEISHU_ENCRYPT_KEY=your_encrypt_key
MANAGEMENT_WEBHOOK=your_administrator_group_webhook
KV_NAMESPACE=TOTP_SERVER
```

4. Add the OTP secrets to the KV namespace `TOTP_SERVER` (secrets are not cached; they are read from KV every time a dynamic code is generated):
   - Default secret: key `TOTP_SECRET`, value is the base32 TOTP secret
   - Named secrets: key `{UPPERCASE_PINYIN}_TOTP_SECRET`, e.g. when a user sends "阿里云OTP" the code reads `ALIYUN_TOTP_SECRET`

5. Configure the domain and other basic information for the Maker container

6. Fill in the callback URL `https://[your-domain]/api/feishu_callback` as the event request URL, and select the connection mode "Send events to developer server"

## Contact

If you have any questions or suggestions, feel free to provide feedback through the Gitee platform.
