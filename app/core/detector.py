import time
from app.state import flow_table, flow_lock, detection_history, latest_prediction
from app.core.features import build_features_from_flow
from app.services.model_service import model_service
from app.config import logger

def monitor_loop():
    logger.info("Starting monitoring loop...")
    while True:
        time.sleep(1)
        active_flows, stale_keys = [], []
        
        with flow_lock:
            if not flow_table: continue
            for key, flow in flow_table.items():
                total_pkts = len(flow.src_packets) + len(flow.dst_packets)
                age = time.time() - flow.start_time
                if total_pkts >= 3: active_flows.append((key, flow))
                if age > 30 or flow.is_finished: stale_keys.append(key)
            for k in stale_keys:
                if k not in [af[0] for af in active_flows]: del flow_table[k]

        if not active_flows: continue

        attack_detected, max_confidence, attack_flow_info = False, 0.0, None

        for key, flow in active_flows:
            try:
                features = build_features_from_flow(flow)
                pred, confidence, proba = model_service.predict(features)

                if pred == 1:
                    attack_detected = True
                    if confidence > max_confidence:
                        max_confidence = confidence
                        attack_flow_info = {
                            "src": flow.src_ip, "dst": flow.dst_ip, "sport": flow.sport,
                            "dport": flow.dport, "proto": flow.proto,
                            "spkts": len(flow.src_packets), "dpkts": len(flow.dst_packets),
                            "state": flow.state
                        }
                    detection_history.append({
                        "timestamp": time.time(), "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "ATTACK", "confidence": confidence,
                        "flow": f"{flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}",
                        "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.proto, str(flow.proto)),
                        "spkts": len(flow.src_packets), "dpkts": len(flow.dst_packets)
                    })
            except Exception as e:
                logger.error(f"Prediction error for flow {key}: {e}")

        global latest_prediction
        timestamp = time.strftime("%H:%M:%S")
        if attack_detected:
            latest_prediction.update({
                "status": "ATTACK", "prediction": 1, "confidence": round(max_confidence, 4),
                "timestamp": time.time(), "active_flows": len(active_flows), "attack_flow": attack_flow_info
            })
            logger.warning(f"[{timestamp}] 🚨 ATTACK DETECTED! Conf: {max_confidence:.2%} | Flows: {len(active_flows)}")
        else:
            latest_prediction.update({
                "status": "OK", "prediction": 0, "confidence": 1.0,
                "timestamp": time.time(), "active_flows": len(active_flows)
            })
            logger.info(f"[{timestamp}] ✅ Status: OK | Active Flows: {len(active_flows)}")

        with flow_lock:
            for key, flow in active_flows:
                if flow.is_finished and key in flow_table: del flow_table[key]
