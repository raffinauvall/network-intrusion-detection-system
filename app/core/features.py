import time
from app.state import connection_log, connection_log_lock
from app.utils.network import get_service, compute_jitter, compute_loss
from app.schemas.traffic import FEATURE_COLUMNS
from app.config import LOOKBACK_WINDOW


def count_ct_features(dst_ip, src_ip, service, dport, sport, flow_sttl, flow_state):
    """
    Compute UNSW-NB15 connection tracking features.

    ct_state_ttl: count of connections with the SAME state AND same TTL bucket.
    Other ct_* features count unique connections to/from src/dst within lookback window.
    """
    now = time.time()

    ct = {
        "ct_dst_ltm": 0, "ct_src_ltm": 0, "ct_dst_src_ltm": 0,
        "ct_srv_src": 0, "ct_srv_dst": 0, "ct_dst_sport_ltm": 0,
        "ct_src_dport_ltm": 0, "ct_state_ttl": 0
    }

    # TTL buckets: UNSW-NB15 groups TTL by OS type
    # Linux: 64, Windows: 128, Cisco: 255, Solaris/AIX: 252-254
    def ttl_bucket(ttl):
        if ttl <= 64: return 64
        if ttl <= 128: return 128
        return 255

    src_ttl_bucket = ttl_bucket(flow_sttl)

    with connection_log_lock:
        entries = list(connection_log)

    for entry in entries:
        if now - entry["time"] > LOOKBACK_WINDOW:
            continue
        # ct_state_ttl: same TTL bucket AND same state
        if entry.get("ttl_bucket") == src_ttl_bucket and entry.get("state") == flow_state:
            ct["ct_state_ttl"] += 1
        if entry["dst_ip"] == dst_ip: ct["ct_dst_ltm"] += 1
        if entry["src_ip"] == src_ip: ct["ct_src_ltm"] += 1
        if entry["dst_ip"] == dst_ip and entry["src_ip"] == src_ip: ct["ct_dst_src_ltm"] += 1
        if entry["service"] == service and entry["src_ip"] == src_ip: ct["ct_srv_src"] += 1
        if entry["service"] == service and entry["dst_ip"] == dst_ip: ct["ct_srv_dst"] += 1
        if entry["dst_ip"] == dst_ip and entry["sport"] == sport: ct["ct_dst_sport_ltm"] += 1
        if entry["src_ip"] == src_ip and entry["dport"] == dport: ct["ct_src_dport_ltm"] += 1

    return ct


def build_features_from_flow(flow) -> dict:
    """Build the 42 raw model-input fields from a live FlowRecord prototype."""
    feat = {f: 0.0 for f in FEATURE_COLUMNS}
    spkts = len(flow.src_packets)
    dpkts = len(flow.dst_packets)
    service = get_service(flow.dport)
    feat.update({
        "proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(flow.proto, str(flow.proto)),
        "service": service,
        "state": flow.state,
    })

    if spkts == 0:
        return feat

    dur = max(flow.last_time - flow.start_time, 0.001)
    sbytes = sum(p[1] for p in flow.src_packets)

    # --- Source-side metrics ---
    feat["dur"] = dur
    feat["sbytes"] = sbytes
    feat["spkts"] = spkts
    feat["smean"] = sbytes / spkts
    feat["sload"] = (sbytes * 8) / dur
    feat["sttl"] = flow.src_ttls[0] if flow.src_ttls else 0
    feat["sjit"] = compute_jitter(flow.src_packets)
    feat["sloss"] = compute_loss(flow.src_packets)

    if spkts > 1:
        intervals = [flow.src_packets[i][0] - flow.src_packets[i-1][0] for i in range(1, spkts)]
        feat["sinpkt"] = (sum(intervals) / len(intervals)) * 1000

    # --- Destination-side metrics (only if we actually have response packets) ---
    if dpkts > 0:
        dbytes = sum(p[1] for p in flow.dst_packets)
        feat["dbytes"] = dbytes
        feat["dpkts"] = dpkts
        feat["dmean"] = dbytes / dpkts
        feat["dload"] = (dbytes * 8) / dur
        feat["dttl"] = flow.dst_ttls[0] if flow.dst_ttls else 0
        feat["djit"] = compute_jitter(flow.dst_packets)
        feat["dloss"] = compute_loss(flow.dst_packets)

        if dpkts > 1:
            d_intervals = [flow.dst_packets[i][0] - flow.dst_packets[i-1][0] for i in range(1, dpkts)]
            feat["dinpkt"] = (sum(d_intervals) / len(d_intervals)) * 1000

    # --- Combined ---
    feat["rate"] = (spkts + dpkts) / dur

    # --- TCP-specific features (only if TCP) ---
    if flow.proto == 6:
        if flow.src_tcp_seq: feat["stcpb"] = flow.src_tcp_seq[0]
        if flow.dst_tcp_seq: feat["dtcpb"] = flow.dst_tcp_seq[0]
        if flow.src_tcp_win: feat["swin"] = flow.src_tcp_win[0]
        if flow.dst_tcp_win: feat["dwin"] = flow.dst_tcp_win[0]
        if flow.syn_time and flow.synack_time:
            feat["tcprtt"] = flow.synack_time - flow.syn_time
            feat["synack"] = flow.synack_time - flow.syn_time
        if flow.synack_time and flow.ack_time:
            feat["ackdat"] = flow.ack_time - flow.synack_time

    # --- Connection tracking features (ct_*) ---
    sttl = feat["sttl"]
    state = flow.state
    ct = count_ct_features(flow.dst_ip, flow.src_ip, service, flow.dport, flow.sport, sttl, state)
    feat.update(ct)

    # --- Boolean features ---
    if flow.src_ip == flow.dst_ip and flow.sport == flow.dport:
        feat["is_sm_ips_ports"] = 1.0

    return feat
