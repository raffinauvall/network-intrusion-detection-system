import os
import logging
import warnings
from pathlib import Path

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress noisy loggers
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning)

APP_TITLE = "UNSW-NB15 IDS Model API"
APP_DESCRIPTION = "FastAPI prototype for serving a Random Forest IDS pipeline."
APP_VERSION = "3.0"

BASE_DIR = Path(__file__).resolve().parents[1]


def _get_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default


def _get_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default


def _get_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_csv_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


_MODEL_PATH = os.environ.get(
    "MODEL_PATH",
    os.environ.get("NIDS_MODEL_PATH", "models/random_forest_ids_pipeline.pkl"),
)
MODEL_PATH = Path(_MODEL_PATH).expanduser()
if not MODEL_PATH.is_absolute():
    MODEL_PATH = BASE_DIR / MODEL_PATH

API_TOKEN = os.environ.get("NIDS_API_TOKEN", "").strip()
LOOKBACK_WINDOW = _get_int_env("NIDS_LOOKBACK_WINDOW", 100)
STALE_FLOW_TIMEOUT = _get_int_env("NIDS_STALE_FLOW_TIMEOUT", 30)
PREDICTION_INTERVAL = _get_float_env("NIDS_PREDICTION_INTERVAL", 1.0)
MIN_SRC_PACKETS = _get_int_env("NIDS_MIN_SRC_PACKETS", 1)
LIVE_FLOW_ALERT_THRESHOLD = _get_int_env("NIDS_LIVE_FLOW_ALERT_THRESHOLD", 100)
MAX_INSPECT_FEATURES = _get_int_env("NIDS_MAX_INSPECT_FEATURES", 250)
CONFIDENCE_THRESHOLD = _get_float_env("NIDS_CONFIDENCE_THRESHOLD", 0.80)
REQ_CONFIDENCE_THRESHOLD = _get_float_env("NIDS_REQ_CONFIDENCE_THRESHOLD", CONFIDENCE_THRESHOLD)
MONITORING_MODE = os.environ.get("NIDS_MONITORING_MODE", "inbound").strip().lower()
ENABLE_SNIFFER = _get_bool_env("NIDS_ENABLE_SNIFFER", False)
ENABLE_AUTO_BLOCK = _get_bool_env("NIDS_ENABLE_AUTO_BLOCK", False)
MONITOR_LOOPBACK = _get_bool_env("NIDS_MONITOR_LOOPBACK", False)
BLOCK_MODE = os.environ.get("NIDS_BLOCK_MODE", "internal").strip().lower()
BLOCK_REASON = os.environ.get("NIDS_BLOCK_REASON", "attack_detected").strip() or "attack_detected"
BLOCKLIST_PATH = Path(os.environ.get("NIDS_BLOCKLIST_PATH", str(BASE_DIR / "blocked_ips.json")))

# Network interface configuration. Set via environment variable for deployment.
# Examples:
#   export NIDS_INTERFACES="eth0"
#   export NIDS_INTERFACES="eth0,ens3"
#   export NIDS_INTERFACES=""              # auto-detect active interfaces
TARGET_INTERFACES = _get_csv_env("NIDS_INTERFACES")
WHITELIST_IPS = set(_get_csv_env("NIDS_WHITELIST_IPS"))
