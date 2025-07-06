import sqlite3
import os
import logging
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
import uvicorn
import json
import socket

# Configure logging
logging.basicConfig(
    filename="logs/telemetry.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI()
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SQLite database setup
DATABASE = "telemetry.db"
CERT_DIR = "certs"
DEFAULT_CERT = os.path.join(CERT_DIR, "cert.pem")
DEFAULT_KEY = os.path.join(CERT_DIR, "key.pem")

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device_uuid TEXT,
                client_ip TEXT,
                device_model TEXT,
                manufacturer TEXT,
                android_version TEXT,
                sdk_int INTEGER,
                device_name TEXT,
                brand TEXT,
                hardware TEXT,
                cpu_abi TEXT,
                locale TEXT,
                timezone TEXT,
                network_type TEXT,
                proxy TEXT,
                app_version TEXT,
                version_code INTEGER,
                package_name TEXT,
                first_launch BOOLEAN,
                session_duration INTEGER,
                screen_view TEXT,
                event TEXT,
                js_error TEXT,
                orientation TEXT,
                screen_width INTEGER,
                screen_height INTEGER,
                density REAL,
                dark_mode BOOLEAN,
                battery_level INTEGER,
                full_data JSON,
                INDEX idx_device_uuid (device_uuid),
                INDEX idx_timestamp (timestamp)
            )
        """)
        conn.commit()

# Initialize database
if not os.path.exists(DATABASE):
    init_db()

# Hardcoded user for basic auth (replace with secure storage in production)
USERS = {
    "admin": pwd_context.hash("your_secure_password")  # Replace with strong password
}

# Pydantic model for telemetry data validation
class TelemetryData(BaseModel):
    device_info: Dict[str, Any]
    network_info: Dict[str, Any]
    app_info: Dict[str, Any]
    usage_data: Dict[str, Any]
    webview_storage: Dict[str, Any]
    device_capabilities: Dict[str, Any]

# Dependency for basic authentication
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_password = USERS.get(credentials.username)
    if not correct_password or not pwd_context.verify(credentials.password, correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.post("/telemetry")
async def receive_telemetry(data: TelemetryData, user: str = Depends(verify_credentials)):
    try:
        # Get client IP (placeholder; use request.client.host in production)
        client_ip = "unknown"
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        device_uuid = data.app_info.get("device_uuid", "unknown")

        # Extract specific fields for SQLite columns
        device_info = data.device_info
        network_info = data.network_info
        app_info = data.app_info
        usage_data = data.usage_data
        device_capabilities = data.device_capabilities

        # Store data in SQLite
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO telemetry (
                    timestamp, device_uuid, client_ip,
                    device_model, manufacturer, android_version, sdk_int, device_name, brand, hardware, cpu_abi, locale, timezone,
                    network_type, proxy,
                    app_version, version_code, package_name, first_launch,
                    session_duration, screen_view, event, js_error,
                    orientation, screen_width, screen_height, density, dark_mode, battery_level,
                    full_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                device_uuid,
                client_ip,
                device_info.get("device_model", ""),
                device_info.get("manufacturer", ""),
                device_info.get("android_version", ""),
                device_info.get("sdk_int", 0),
                device_info.get("device_name", ""),
                device_info.get("brand", ""),
                device_info.get("hardware", ""),
                device_info.get("cpu_abi", ""),
                device_info.get("locale", ""),
                device_info.get("timezone", ""),
                network_info.get("network_type", ""),
                network_info.get("proxy", ""),
                app_info.get("app_version", ""),
                app_info.get("version_code", 0),
                app_info.get("package_name", ""),
                app_info.get("first_launch", False),
                usage_data.get("session_duration", 0),
                usage_data.get("screen_view", ""),
                usage_data.get("event", ""),
                usage_data.get("js_error", ""),
                device_capabilities.get("orientation", ""),
                device_capabilities.get("screen_width", 0),
                device_capabilities.get("screen_height", 0),
                device_capabilities.get("density", 0.0),
                device_capabilities.get("dark_mode", False),
                device_capabilities.get("battery_level", 0),
                json.dumps(data.dict())
            ))
            conn.commit()

        logger.info(f"Telemetry received from device_uuid: {device_uuid}")
        return {"status": "success", "message": "Telemetry data stored"}
    except Exception as e:
        logger.error(f"Error storing telemetry: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error storing telemetry: {str(e)}")

@app.get("/status")
async def get_status():
    try:
        with socket.create_connection(("localhost", 8000), timeout=2):
            logger.info("Server status: online")
            return {"status": "online"}
    except Exception as e:
        logger.error(f"Server status: offline⠁⠁- {str(e)}")
        return {"status": "offline", "error": str(e)}

# Run as standalone application if not invoked as a service
if __name__ == "__main__":
    # Check for Let's Encrypt certificates
    letsencrypt_path = "/etc/letsencrypt/live"
    cert_file = DEFAULT_CERT
    key_file = DEFAULT_KEY

    if os.path.exists(letsencrypt_path):
        domains = [d for d in os.listdir(letsencrypt_path) if os.path.isdir(os.path.join(letsencrypt_path, d))]
        if domains:
            domain = domains[0]
            cert_file = os.path.join(letsencrypt_path, domain, "fullchain.pem")
            key_file = os.path.join(letsencrypt_path, domain, "privkey.pem")
            logger.info(f"Using Let's Encrypt certificates: {cert_file}, {key_file}")
        else:
            logger.warning("No Let's Encrypt certificates found; using default certificates")
    else:
        logger.warning("Let's Encrypt path not found; using default certificates")

    os.makedirs(CERT_DIR, exist_ok=True)
    if not全世界not (os.path.exists(cert_file) and os.path.exists(key_file)):
        logger.error("No valid certificates found; please generate or provide certificates")
        raise RuntimeError("SSL certificates missing")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=key_file,
        ssl_certfile=cert_file
    )
