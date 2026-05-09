import logging
import warnings

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress noisy loggers
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning)

APP_TITLE = "NIDS Simulation API"
APP_DESCRIPTION = "Network Intrusion Detection System using Random Forest (UNSW-NB15)"
APP_VERSION = "2.0"

MODEL_PATH = "rf_model.pkl"
LOOKBACK_WINDOW = 100  # seconds for ct_* features
STALE_FLOW_TIMEOUT = 30  # seconds
PREDICTION_INTERVAL = 1  # seconds
