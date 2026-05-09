import time
from app.state import connection_log
from app.utils.network import get_service, compute_jitter, compute_loss
from app.services.model_service import model_service

def count_ct_features(dst_ip, src_ip, service, dport, sport):
    now = time.time()
    lookback = 100
    
    ct = {
        "ct_dst_ltm": 0, "ct_src_ltm": 0, "ct_dst_src_ltm": 0,
        "ct_srv_src": 0, "ct_srv_dst": 0, "ct_dst_sport_ltm": 0, "ct_src_dport_ltm": 0
    }

    for entry in connection_log:
        if now - entry["time"] > lookback:
            continue
        if entry["dst_ip"] == dst_ip: ct["ct_dst_ltm"] += 1
        if entry["src_ip"] == src_ip: ct["ct_src_ltm"] += 1
        if entry["dst_ip"] == dst_ip and entry["src_ip"] == src_ip: ct["ct_dst_src_ltm"] += 1
        if entry["service"] == service and entry["src_ip"] == src_ip: ct["ct_srv_src"] += 1
        if entry["service"] == service and entry["dst_ip"] == dst_ip: ct["ct_srv_dst"] += 1
        if entry["dst_ip"] == dst_ip and entry["sport"] == sport: ct["ct_dst_sport_ltm"] += 1
        if entry["src_ip"] == src_ip and entry["dport"] == dport: ct["ct_src_dport_ltm"] += 1
    return ct

def build_features_from_flow(flow) -> dict:
    feat = {f: 0.0 for f in model_service.features}
    spkts = len(flow.src_packets)
    dpkts = len(flow.dst_packets)
    if spkts == 0: return feat

    dur = max(flow.last_time - flow.start_time, 0.001)
    sbytes = sum(p[1] for p in flow.src_packets)
    dbytes = sum(p[1] for p in flow.dst_packets)

    feat.update({
        "dur": dur, "sbytes": sbytes, "spkts": spkts, "smean": sbytes / spkts,
        "sload": (sbytes * 8) / dur, "sttl": flow.src_ttls[0] if flow.src_ttls else 0,
        "rate": (spkts + dpkts) / dur, "dbytes": dbytes, "dpkts": dpkts,
        "dmean": dbytes / dpkts if dpkts > 0 else 0, "dload": (dbytes * 8) / dur if dur > 0 else 0,
        "dttl": flow.dst_ttls[0] if flow.dst_ttls else 0,
        "sjit": compute_jitter(flow.src_packets), "djit": compute_jitter(flow.dst_packets),
        "sloss": compute_loss(flow.src_packets), "dloss": compute_loss(flow.dst_packets)
    })

    if spkts > 1:
        feat["sinpkt"] = (sum(flow.src_packets[i][0] - flow.src_packets[i-1][0] for i in range(1, spkts)) / (spkts-1)) * 1000
    if dpkts > 1:
        feat["dinpkt"] = (sum(flow.dst_packets[i][0] - flow.dst_packets[i-1][0] for i in range(1, dpkts)) / (dpkts-1)) * 1000

    if flow.proto == 6:  # TCP
        if flow.src_tcp_seq: feat["stcpb"] = flow.src_tcp_seq[0]
        if flow.dst_tcp_seq: feat["dtcpb"] = flow.dst_tcp_seq[0]
        if flow.src_tcp_win: feat["swin"] = flow.src_tcp_win[0]
        if flow.dst_tcp_win: feat["dwin"] = flow.dst_tcp_win[0]
        if flow.syn_time and flow.synack_time:
            feat["tcprtt"] = flow.synack_time - flow.syn_time
            feat["synack"] = flow.synack_time - flow.syn_time
        if flow.synack_time and flow.ack_time:
            feat["ackdat"] = flow.ack_time - flow.synack_time

    feat["ct_state_ttl"] = min(len([e for e in connection_log if time.time() - e["time"] < 100]), 255)
    service = get_service(flow.dport)
    feat.update(count_ct_features(flow.dst_ip, flow.src_ip, service, flow.dport, flow.sport))
    if flow.src_ip == flow.dst_ip and flow.sport == flow.dport: feat["is_sm_ips_ports"] = 1.0

    proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(flow.proto, "unas")
    if f"proto_{proto_name}" in feat: feat[f"proto_{proto_name}"] = 1.0
    if f"service_{service}" in feat: feat[f"service_{service}"] = 1.0
    
    state_key = flow.state if f"state_{flow.state}" in feat else "CON"
    if f"state_{state_key}" in feat: feat[f"state_{state_key}"] = 1.0

    return feat
