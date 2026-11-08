import logging
import os

os.makedirs("logs", exist_ok=True)

logger = logging.getLogger("security_audit")
logger.setLevel(logging.INFO)

# Wyczyszczenie starych uchwytów, aby nie dublować wpisów
if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s | [%(levelname)s] | %(message)s")
    file_handler = logging.FileHandler("logs/audit.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def log_event(ip: str, action: str, username: str, status: str, details: str = ""):
    logger.info(f"IP={ip} | ACTION={action} | USER={username} | STATUS={status} | DETAILS={details}")