# Android Telemetry Server

**Author:** Thibaut Lombard  
**Date:** July 5, 2025  
**Handle:** @lombardweb



## Python FastAPI Telemetry API

This Python FastAPI interface securely transfers telemetry data from your Android APK users to a Python FastAPI server.



## 📦 Setup Instructions



### 1️⃣ Prepare the Environment


- Make sure you’re running **Ubuntu 20.04+** with **Python 3.8+**.
- Install OpenSSL if it’s not already installed:

   ```bash
   sudo apt update
   sudo apt install openssl
   ```



### 2️⃣ Install Dependencies


The setup script will install required Python packages, but you can install them manually:

```bash
pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart sqlalchemy
```



### 3️⃣ Create Project Directory

```bash
mkdir telemetry_server
cd telemetry_server
mkdir logs certs
```


### 4️⃣ Save Scripts

- Place `main.py` and `setup_telemetry_service.py` in the `telemetry_server` directory.
- Make sure `main.py` includes the correct password in the `USERS` list.


### 5️⃣ Run the Setup Script

```bash
python3 setup_telemetry_service.py
```

- **Certificate Prompt:**  
  If `/etc/letsencrypt/live` exists, the script lists available domains and asks if you want to use Let’s Encrypt certificates.  
  If not, or if you decline, it generates self-signed certificates with `openssl`.

- **Service Prompt:**  
  You’ll be asked if you want to install the server as a **systemd** service (`y`) or run it as a standalone app (`n`).

  - If you choose **systemd**, the script:
    - Installs dependencies
    - Creates and enables `telemetry.service`
    - Starts the service

  - If you choose **standalone**, it simply runs `main.py`.



## 🔌 Manage the Service (if installed as systemd)

```bash
# Start the service
sudo systemctl start telemetry.service

# Stop the service
sudo systemctl stop telemetry.service

# Check status
sudo systemctl status telemetry.service

# View logs
cat logs/telemetry.log

# Enable on boot
sudo systemctl enable telemetry.service
```


## ✅ Check the Status Endpoint

Visit:

```
https://your-server-ip:8000/status
```

- Returns: `{"status": "online"}` or `{"status": "offline", "error": "..."}`.



## 📲 Update the Android App

Make sure your `TelemetryManager.kt` in your Android app points to your server’s HTTPS endpoint (for example: `https://your-server-ip:8000/telemetry`).

Include basic authentication credentials:

```kotlin
val credentials = Credentials.basic("admin", "your_secure_password")
```



## ⚙️ Features

- **Systemd Service**: Optional installation as a systemd service with automatic start/stop/status handling.
- **Certificate Handling**:  
  - Uses Let’s Encrypt if available  
  - Or generates self-signed certs with OpenSSL
  - Always enforces HTTPS with Uvicorn’s SSL support
- **Standalone Mode**: Can run without systemd if you prefer.
- **Status Endpoint**: `/status` to check server health.
- **Logging**: Logs activity and errors to `logs/telemetry.log`.
- **Security**:
  - HTTPS enforced
  - Basic Auth with bcrypt-hashed passwords
  - Validates JSON payloads with Pydantic
- **SQLite Storage**: Saves telemetry in a local database (`telemetry.db`).
- **Privacy Compliance**: Uses `device_uuid` to anonymize users — be sure to update your privacy policy.



## 🧪 Example Usage

**Install:**

```bash
python3 setup_telemetry_service.py
```



**Sample interaction:**

```text
2025-07-06 17:06:00,123 - INFO - Starting telemetry server installation...
Found Let’s Encrypt domains: ['example.com']
Use Let’s Encrypt certificates? (y/n): y
Enter domain (e.g., example.com): example.com
Install as a systemd service? (y/n, default: n): y
2025-07-06 17:06:05,456 - INFO - Dependencies installed
2025-07-06 17:06:06,789 - INFO - Systemd service created and enabled
2025-07-06 17:06:07,012 - INFO - Telemetry service started
Service installed and started. Check status with: sudo systemctl status telemetry.service
```



**Check Status:**

```bash
curl -k https://your-server-ip:8000/status
# Response: {"status": "online"}
```

**Query Stored Telemetry:**

```bash
sqlite3 telemetry.db "SELECT * FROM telemetry;"
```




## ⚡ Notes


- **Production Certificates:**  
  Always prefer Let’s Encrypt for production to avoid browser warnings. Install Certbot and generate your certs:

  ```bash
  sudo apt install certbot
  sudo certbot certonly --standalone -d your-domain.com
  ```

- **Client IP:**  
  Replace `client_ip = "unknown"` in `main.py` with `request.client.host` for production.  
  Be sure to parse headers like `X-Forwarded-For` if behind a proxy.

- **Security:**  
  - Store credentials securely (e.g., in environment variables).
  - Restrict access to `telemetry.db` and `certs/`:

    ```bash
    chmod 600 certs/*
    ```

- **Error Handling:**  
  Logs errors to `logs/telemetry.log` and sends meaningful HTTP responses.

- **Testing:**  
  Use `curl -k` for self-signed certificates or configure OkHttp to trust self-signed certs in your Android app.




## 📊 Example Telemetry Payload



Below is an example of the telemetry data structure stored in `telemetry.db`:

```json
{
  "device_info": {
    "device_model": "Pixel 7",
    "manufacturer": "Google",
    "android_version": "14",
    "sdk_int": 34,
    "device_name": "walleye",
    "brand": "Google",
    "hardware": "exynos9820",
    "cpu_abi": "arm64-v8a",
    "locale": "en-US",
    "timezone": "Europe/Paris"
  },
  "network_info": {
    "network_type": "wifi",
    "ip_address": "logged_server_side",
    "proxy": "none"
  },
  "app_info": {
    "app_version": "1.0.0",
    "version_code": 1,
    "package_name": "com.example.myapp",
    "first_launch": false,
    "device_uuid": "550e8400-e29b-41d4-a716-446655440000"
  },
  "usage_data": {
    "timestamp": "2025-07-06T12:35:00Z",
    "session_duration": 145,
    "screen_view": "MainActivity",
    "event": "link_clicked",
    "js_error": "none"
  },
  "webview_storage": {
    "local_storage": { "key": "value" },
    "cookies": "session_id=abc123"
  },
  "device_capabilities": {
    "orientation": "portrait",
    "screen_width": 1080,
    "screen_height": 1920,
    "density": 3.0,
    "dark_mode": true,
    "battery_level": 87
  }
}
```


## License

![Creative Commons BY-NC-SA](https://github.com/Lombard-Web-Services/Android-Telemetry/blob/main/CC_BY-NC-SA.svg.png?raw=true)

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike (CC BY-NC-SA)** license.

**What does it mean?**

- **Attribution (BY)**: You must give appropriate credit, provide a link to the license, and indicate if changes were made.
- **NonCommercial (NC)**: You may not use the material for commercial purposes.
- **ShareAlike (SA)**: If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

[Learn more about this license here](https://creativecommons.org/licenses/by-nc-sa/4.0/).



**© Thibaut Lombard — @lombardweb**
