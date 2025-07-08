import os
import logging
import json
import re
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator
from typing import Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, JSON, Index
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from urllib.parse import unquote
from html import escape
from datetime import datetime

# Read configuration
CONFIG_FILE = "config.json"
CREDENTIALS_FILE = "credentials.json"
use_https = True
port = 8000
enable_logging = True

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
        use_https = config.get("use_https", True)
        port = config.get("port", 8000)
        enable_logging = config.get("enable_logging", True)
else:
    logging.warning("Config file not found; using defaults: use_https=True, port=8000, enable_logging=True")

# Configure logging
if enable_logging:
    logging.basicConfig(
        filename="logs/telemetry.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
logger = logging.getLogger(__name__)

# Read credentials
USERS = {}
if os.path.exists(CREDENTIALS_FILE):
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            creds = json.load(f)
            USERS = {creds["username"]: creds["hashed_password"]}
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load credentials: {e}")
        raise RuntimeError(f"Failed to load credentials: {e}")
else:
    logger.error("Credentials file not found")
    raise RuntimeError("Credentials file not found")

# FastAPI app
app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://lombard-web-services.com"],  # Updated with your domain
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none';"
    if use_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# SQLite database setup with SQLAlchemy
DATABASE = "telemetry.db"
DATABASE_URL = f"sqlite:///{DATABASE}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SQLAlchemy model
class Telemetry(Base):
    __tablename__ = "telemetry"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    device_uuid = Column(String, index=True)
    client_ip = Column(String)
    device_model = Column(String)
    manufacturer = Column(String)
    android_version = Column(String)
    sdk_int = Column(Integer)
    device_name = Column(String)
    brand = Column(String)
    hardware = Column(String)
    cpu_abi = Column(String)
    locale = Column(String)
    timezone = Column(String)
    network_type = Column(String)
    proxy = Column(String)
    app_version = Column(String)
    version_code = Column(Integer)
    package_name = Column(String)
    first_launch = Column(Boolean)
    session_duration = Column(Integer)
    screen_view = Column(String)
    event = Column(String)
    js_error = Column(String)
    orientation = Column(String)
    screen_width = Column(Integer)
    screen_height = Column(Integer)
    density = Column(Float)
    dark_mode = Column(Boolean)
    battery_level = Column(Integer)
    full_data = Column(JSON)

    __table_args__ = (
        Index("idx_device_uuid", "device_uuid"),
        Index("idx_timestamp", "timestamp"),
    )

# Initialize database
Base.metadata.create_all(bind=engine)

# Pydantic models for strict validation
def sanitize_string(cls, v):
    """Sanitize string fields to prevent injection."""
    v = unquote(escape(v))
    if re.search(r'[<>;{}]', v):
        raise ValueError("Invalid characters detected")
    return v

class DeviceInfo(BaseModel):
    device_model: str = Field(..., max_length=100)
    manufacturer: str = Field(..., max_length=100)
    android_version: str = Field(..., max_length=20)
    sdk_int: int = Field(..., ge=1)
    device_name: str = Field(..., max_length=100)
    brand: str = Field(..., max_length=100)
    hardware: str = Field(..., max_length=100)
    cpu_abi: str = Field(..., max_length=200)
    locale: str = Field(..., max_length=20)
    timezone: str = Field(..., max_length=50)

    @validator("device_model", "manufacturer", "device_name", "brand", "hardware", "cpu_abi", "locale", "timezone")
    def validate_device_info(cls, v):
        return sanitize_string(cls, v)

class NetworkInfo(BaseModel):
    network_type: str = Field(..., max_length=20)
    ip_address: str = Field(..., max_length=50)
    proxy: str = Field(..., max_length=100)

    @validator("network_type", "proxy")
    def validate_network_info(cls, v):
        return sanitize_string(cls, v)

class AppInfo(BaseModel):
    app_version: str = Field(..., max_length=20)
    version_code: int = Field(..., ge=1)
    package_name: str = Field(..., max_length=100)
    first_launch: bool
    device_uuid: str = Field(..., max_length=36)

    @validator("app_version", "package_name", "device_uuid")
    def validate_app_info(cls, v):
        return sanitize_string(cls, v)

class UsageData(BaseModel):
    timestamp: str = Field(..., max_length=30)
    session_duration: int = Field(..., ge=0)
    screen_view: str = Field(..., max_length=100)
    event: str = Field(..., max_length=100)
    js_error: str = Field(..., max_length=200)

    @validator("screen_view", "event", "js_error")
    def validate_usage_data(cls, v):
        return sanitize_string(cls, v)

class WebviewStorage(BaseModel):
    local_storage: Dict[str, Any]
    cookies: str = Field(..., max_length=500)

    @validator("cookies")
    def validate_webview_storage(cls, v):
        return sanitize_string(cls, v)

class DeviceCapabilities(BaseModel):
    orientation: str = Field(..., max_length=20)
    screen_width: int = Field(..., ge=0)
    screen_height: int = Field(..., ge=0)
    density: float = Field(..., ge=0.0)
    dark_mode: bool
    battery_level: int = Field(..., ge=0, le=100)

    @validator("orientation")
    def validate_device_capabilities(cls, v):
        return sanitize_string(cls, v)

class TelemetryData(BaseModel):
    device_info: DeviceInfo
    network_info: NetworkInfo
    app_info: AppInfo
    usage_data: UsageData
    webview_storage: WebviewStorage
    device_capabilities: DeviceCapabilities

# Basic auth setup
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency for basic authentication
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_password = USERS.get(credentials.username)
    if not correct_password or not pwd_context.verify(credentials.password, correct_password):
        if enable_logging:
            logger.warning(f"Authentication failed for user: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/telemetry")
@limiter.limit("10/minute")
async def receive_telemetry(request: Request, data: TelemetryData, user: str = Depends(verify_credentials), db: Session = Depends(get_db)):
    try:
        client_ip = request.client.host or "unknown"
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        device_uuid = data.app_info.device_uuid

        telemetry = Telemetry(
            timestamp=timestamp,
            device_uuid=device_uuid,
            client_ip=client_ip,
            device_model=data.device_info.device_model,
            manufacturer=data.device_info.manufacturer,
            android_version=data.device_info.android_version,
            sdk_int=data.device_info.sdk_int,
            device_name=data.device_info.device_name,
            brand=data.device_info.brand,
            hardware=data.device_info.hardware,
            cpu_abi=data.device_info.cpu_abi,
            locale=data.device_info.locale,
            timezone=data.device_info.timezone,
            network_type=data.network_info.network_type,
            proxy=data.network_info.proxy,
            app_version=data.app_info.app_version,
            version_code=data.app_info.version_code,
            package_name=data.app_info.package_name,
            first_launch=data.app_info.first_launch,
            session_duration=data.usage_data.session_duration,
            screen_view=data.usage_data.screen_view,
            event=data.usage_data.event,
            js_error=data.usage_data.js_error,
            orientation=data.device_capabilities.orientation,
            screen_width=data.device_capabilities.screen_width,
            screen_height=data.device_capabilities.screen_height,
            density=data.device_capabilities.density,
            dark_mode=data.device_capabilities.dark_mode,
            battery_level=data.device_capabilities.battery_level,
            full_data=data.dict()
        )

        db.add(telemetry)
        db.commit()
        if enable_logging:
            logger.info(f"Telemetry stored for device_uuid: {device_uuid}, IP: {client_ip}")
        return {"status": "success", "message": "Telemetry data stored"}
    except Exception as e:
        db.rollback()
        if enable_logging:
            logger.error(f"Error storing telemetry: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error storing telemetry: {str(e)}")

@app.get("/status")
@limiter.limit("5/minute")
async def get_status(request: Request):
    try:
        if enable_logging:
            logger.info("Server status: online")
        return {"status": "online"}
    except Exception as e:
        if enable_logging:
            logger.error(f"Server status: offline - {str(e)}")
        return {"status": "offline", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    cert_file = os.path.join("certs", "cert.pem")
    key_file = os.path.join("certs", "key.pem")
    if use_https:
        if not (os.path.exists(cert_file) and os.path.exists(key_file)):
            if enable_logging:
                logger.error("No valid certificates found; please provide certificates for HTTPS")
            raise RuntimeError("SSL certificates missing")
        uvicorn.run(app, host="0.0.0.0", port=port, ssl_keyfile=key_file, ssl_certfile=cert_file)
    else:
        uvicorn.run(app, host="0.0.0.0", port=port)
