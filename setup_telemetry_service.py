import os
import subprocess
import shutil
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
CERT_DIR = os.path.join(PROJECT_DIR, "certs")
SERVICE_FILE = "/etc/systemd/system/telemetry.service"
LETSENCRYPT_PATH = "/etc/letsencrypt/live"

def generate_self_signed_cert():
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
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate certificates: {e}")
        sys.exit(1)

def create_systemd_service():
    service_content = f"""
[Unit]
Description=Telemetry FastAPI Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 {os.path.join(PROJECT_DIR, "main.py")}
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

def install():
    logger.info("Starting telemetry server installation...")
    
    # Ensure logs directory exists
    os.makedirs(os.path.join(PROJECT_DIR, "logs"), exist_ok=True)

    # Check for Let's Encrypt certificates
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    use_letsencrypt = False

    if os.path.exists(LETSENCRYPT_PATH):
        domains = [d for d in os.listdir(LETSENCRYPT_PATH) if os.path.isdir(os.path.join(LETSENCRYPT_PATH, d))]
        if domains:
            logger.info(f"Found Let's Encrypt certificates in {LETSENCRYPT_PATH}")
            print(f"Found Let's Encrypt domains: {domains}")
            use_letsencrypt = input("Use Let's Encrypt certificates? (y/n): ").lower() == "y"
            if use_letsencrypt:
                domain = input(f"Enter domain (e.g., {domains[0]}): ") or domains[0]
                cert_file = os.path.join(LETSENCRYPT_PATH, domain, "fullchain.pem")
                key_file = os.path.join(LETSENCRYPT_PATH, domain, "privkey.pem")

    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        logger.info("No valid certificates found")
        generate_cert = input("Generate self-signed certificates with openssl? (y/n): ").lower() == "y"
        if generate_cert:
            generate_self_signed_cert()
        else:
            logger.error("No certificates provided; exiting")
            sys.exit(1)

    # Prompt for service installation
    install_as_service = input("Install as a systemd service? (y/n, default: n): ").lower() == "y"
    
    if install_as_service:
        # Install dependencies
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "python-jose[cryptography]", "passlib[bcrypt]", "python-multipart", "sqlalchemy"], check=True)
            logger.info("Dependencies installed")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            sys.exit(1)

        # Create systemd service
        create_systemd_service()
        
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
        subprocess.run([sys.executable, os.path.join(PROJECT_DIR, "main.py")])

if __name__ == "__main__":
    install()
