import threading
import time
from collections import deque

# Global State
flow_table = {}         # key: (src_ip, sport, dst_ip, dport) -> FlowRecord
flow_lock = threading.Lock()
detection_history = deque(maxlen=200)
connection_log = deque(maxlen=500)  # For ct_* features
latest_prediction = {"status": "INITIALIZING", "prediction": 0, "timestamp": time.time()}
