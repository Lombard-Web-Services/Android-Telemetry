import os
import subprocess
import shutil
import sys
import logging
import glob
import json
from passlib.context import CryptContext

# Configure temporary logging for setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
CERT_DIR = os.path.join(PROJECT_DIR, "certs")
SERVICE_FILE = "/etc/systemd/system/telemetry.service"
LETSENCRYPT_PATH = "/etc/letsencrypt/live"
CONFIG_FILE = os.path.join(PROJECT_DIR, "config.json")
CREDENTIALS_FILE = os.path.join(PROJECT_DIR, "credentials.json")

def find_certificate_file(base_path, prefix):
    """Find the first available certificate file (e.g., privkey.pem, privkey1.pem, etc.)."""
    for i in range(1, 10):  # Check up to privkey9.pem
        file_name = f"{prefix}{i}.pem" if i > 1 else f"{prefix}.pem"
        file_path = os.path.join(base_path, file_name)
        if os.path.exists(file_path):
            return file_path
    return None

def copy_letsencrypt_certs(domain):
    """Copy Let's Encrypt certificates, resolving symlinks and handling numbered variants."""
    domain_path = os.path.join(LETSENCRYPT_PATH, domain)
    real_path = os.path.realpath(domain_path)  # Resolve symlinks
    logger.info(f"Resolved domain path: {real_path}")

    fullchain_src = find_certificate_file(real_path, "fullchain")
    privkey_src = find_certificate_file(real_path, "privkey")

    if not fullchain_src or not privkey_src:
        logger.error(f"Required certificate files not found in {real_path}")
        return False

    os.makedirs(CERT_DIR, exist_ok=True)
    fullchain_dest = os.path.join(CERT_DIR, "cert.pem")
    privkey_dest = os.path.join(CERT_DIR, "key.pem")

    try:
        shutil.copy(fullchain_src, fullchain_dest)
        shutil.copy(privkey_src, privkey_dest)
        logger.info(f"Copied certificates: {fullchain_src} -> {fullchain_dest}, {privkey_src} -> {privkey_dest}")
        return True
    except (shutil.Error, PermissionError) as e:
        logger.error(f"Failed to copy certificates: {e}")
        return False

def generate_self_signed_cert():
    """Generate self-signed certificates with openssl."""
    logger.info("Generating self-signed certificates...")
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
            "-out", cert_file, "-keyout", key_file, "-days", "365",
            "-subj", "/CN=localhost"
        ], check=True)
        logger.info(f"Certificates generated: {cert_file}, {key_file}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate certificates: {e}")
        return False

def install_dependencies():
    """Install required Python dependencies."""
    dependencies = [
        "fastapi",
        "sqlalchemy",
        "python-jose[cryptography]",
        "passlib[bcrypt]",
        "python-multipart",
        "slowapi",
        "httpx",
        "uvicorn"
    ]
    logger.info("Installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install"] + dependencies, check=True)
        logger.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False

def get_port():
    """Prompt user for port number within valid range."""
    while True:
        try:
            port = input("Enter the port for the API server (1024-65535, default: 8000): ").strip()
            if not port:
                return 8000
            port = int(port)
            if 1024 <= port <= 65535:
                return port
            else:
                print("Port must be between 1024 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def get_credentials():
    """Prompt user for username and password, hash the password."""
    username = input("Enter username for API authentication (default: admin): ").strip() or "admin"
    while True:
        password = input("Enter password for API authentication: ").strip()
        if password:
            break
        print("Password cannot be empty.")
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(password)
    return {"username": username, "hashed_password": hashed_password}

def save_credentials(credentials):
    """Save credentials to a secure file."""
    try:
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(credentials, f)
        os.chmod(CREDENTIALS_FILE, 0o600)  # Restrict permissions
        logger.info(f"Credentials saved to {CREDENTIALS_FILE}")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to save credentials: {e}")
        sys.exit(1)

def create_systemd_service(port):
    """Create and enable systemd service."""
    service_content = f"""
[Unit]
Description=Telemetry FastAPI Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port {port}
WorkingDirectory={PROJECT_DIR}
Restart=always
User={os.getlogin()}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""
    try:
        with open("telemetry.service", "w") as f:
            f.write(service_content)
        subprocess.run(["sudo", "mv", "telemetry.service", SERVICE_FILE], check=True)
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "telemetry.service"], check=True)
        logger.info("Systemd service created and enabled")
    except (subprocess.CalledProcessError, PermissionError) as e:
        logger.error(f"Failed to create systemd service: {e}")
        sys.exit(1)

def save_config(use_https, port, enable_logging):
    """Save configuration to config.json."""
    config = {"use_https": use_https, "port": port, "enable_logging": enable_logging}
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        logger.info(f"Configuration saved: use_https={use_https}, port={port}, enable_logging={enable_logging}")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to save configuration: {e}")
        sys.exit(1)

def install():
    logger.info("Starting telemetry server installation...")
    
    # Ensure logs and certs directories exist
    os.makedirs(os.path.join(PROJECT_DIR, "logs"), exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)

    # Install dependencies
    if not install_dependencies():
        logger.error("Dependency installation failed; exiting")
        sys.exit(1)

    # Prompt for port
    port = get_port()

    # Prompt for credentials
    credentials = get_credentials()
    save_credentials(credentials)

    # Prompt for HTTPS usage
    use_https = input("Use HTTPS for the server? (y/n, default: y): ").lower() != "n"
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    certs_copied = False

    if use_https:
        # Check for Let's Encrypt certificates
        if os.path.exists(LETSENCRYPT_PATH):
            domains = [d for d in os.listdir(LETSENCRYPT_PATH) if os.path.isdir(os.path.join(LETSENCRYPT_PATH, d))]
            if domains:
                logger.info(f"Found Let's Encrypt certificates in {LETSENCRYPT_PATH}")
                print(f"Available domains: {domains}")
                domain = input("Select a domain to copy certificates from (or press Enter to skip): ").strip()
                if domain in domains:
                    certs_copied = copy_letsencrypt_certs(domain)
                else:
                    logger.warning("No domain selected or invalid domain; proceeding to certificate generation prompt")
            else:
                logger.warning("No Let's Encrypt certificates found")
        else:
            logger.warning("Let's Encrypt path not found")

        if not certs_copied and not (os.path.exists(cert_file) and os.path.exists(key_file)):
            logger.info("No valid certificates found")
            generate_cert = input("Generate self-signed certificates with openssl? (y/n): ").lower() == "y"
            if generate_cert:
                if not generate_self_signed_cert():
                    logger.error("Failed to generate certificates; exiting")
                    sys.exit(1)
            else:
                logger.error("No certificates provided; exiting")
                sys.exit(1)

    # Prompt for logging
    enable_logging = input("Enable logging to telemetry.log? (y/n, default: y): ").lower() != "n"

    # Save configuration
    save_config(use_https, port, enable_logging)

    # Prompt for service installation
    install_as_service = input("Install as a systemd service? (y/n, default: n): ").lower() == "y"
    
    if install_as_service:
        # Create systemd service
        create_systemd_service(port)
        
        # Start service
        try:
            subprocess.run(["sudo", "systemctl", "start", "telemetry.service"], check=True)
            logger.info("Telemetry service started")
            print("Service installed and started. Check status with: sudo systemctl status telemetry.service")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start service: {e}")
            sys.exit(1)
    else:
        logger.info("Running as standalone application")
        cmd = [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(port)]
        if use_https:
            cmd.extend(["--ssl-certfile", cert_file, "--ssl-keyfile", key_file])
        subprocess.run(cmd)

if __name__ == "__main__":
    install()
