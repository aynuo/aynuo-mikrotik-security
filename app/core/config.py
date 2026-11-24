import ipaddress
import os
from pathlib import Path

ROOT = Path(getattr(__import__("sys"), "_MEIPASS", Path(__file__).resolve().parents[2]))
if getattr(__import__("sys"), "frozen", False):
    DATA_DIR = Path(os.getenv("LOCALAPPDATA", Path.home())) / "AYNUO" / "data"
else:
    DATA_DIR = ROOT / "data"
REPORT_DIR = DATA_DIR / "reports"
DATABASE = DATA_DIR / "aynuo.db"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".rsc", ".txt"}
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _networks(value: str):
    return tuple(ipaddress.ip_network(item.strip(), strict=False) for item in value.split(",") if item.strip())


SSH_ALLOWED_NETWORKS = _networks(os.getenv(
    "AYNUO_SSH_NETWORKS",
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8",
))
SSH_KNOWN_HOSTS = DATA_DIR / "known_hosts"
LIVE_MAX_CONCURRENT = max(1, min(int(os.getenv("AYNUO_SSH_MAX_CONCURRENT", "2")), 10))
REMOTE_API_TOKEN = os.getenv("AYNUO_API_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

