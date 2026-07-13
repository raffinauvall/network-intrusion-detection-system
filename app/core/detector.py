import threading
import time
from app.state import flow_table, flow_lock, detection_history, latest_prediction
from app.core.features import build_features_from_flow
from app.model import model_service
from app.network import get_local_ips
from app.config import (
    CONFIDENCE_THRESHOLD,
    LIVE_FLOW_ALERT_THRESHOLD,
    MIN_SRC_PACKETS,
    MONITORING_MODE,
    PREDICTION_INTERVAL,
    REQ_CONFIDENCE_THRESHOLD,
    STALE_FLOW_TIMEOUT,
    WHITELIST_IPS,
    MONITOR_LOOPBACK,
    logger,
)

INCOMPLETE_STATES = {"REQ", "INT"}
LOCAL_IPS: set[str] = get_local_ips()


def _is_safe_flow(flow) -> bool:
    if not MONITOR_LOOPBACK and flow.src_ip == "127.0.0.1" and flow.dst_ip == "127.0.0.1":
        return True
    if flow.src_ip in WHITELIST_IPS:
        return True
    return False


def _is_inbound(flow) -> bool:
    return flow.dst_ip in LOCAL_IPS


def _should_monitor(flow) -> bool:
    if _is_safe_flow(flow):
        return False
    if len(flow.src_packets) < MIN_SRC_PACKETS:
        return False
    if MONITORING_MODE == "all":
        return True
    return _is_inbound(flow)


def _history_event(flow, confidence: float) -> dict:
    return {
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "ATTACK",
        "confidence": round(confidence, 4),
        "attacker_ip": flow.src_ip,
        "target_ip": flow.dst_ip,
        "target_port": flow.dport,
        "flow": f"{flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}",
        "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.proto, str(flow.proto)),
        "spkts": len(flow.src_packets),
        "dpkts": len(flow.dst_packets),
        "state": flow.state,
    }


def _flow_info(flow, confidence: float, detector: str) -> dict:
    return {
        "src": flow.src_ip,
        "dst": flow.dst_ip,
        "sport": flow.sport,
        "dport": flow.dport,
        "proto": flow.proto,
        "state": flow.state,
        "confidence": round(confidence, 4),
        "detector": detector,
    }


def monitor_loop(stop_event: threading.Event | None = None):
    stop_event = stop_event or threading.Event()
    logger.info(
        "Prototype live feature extractor monitoring %s traffic to local IPs: %s",
        MONITORING_MODE.upper(),
        sorted(LOCAL_IPS),
    )
    latest_prediction.update({
        "status": "OK",
        "prediction": 0,
        "confidence": 1.0,
        "timestamp": time.time(),
        "active_flows": 0,
        "attacker_ip": None,
        "target_port": None,
        "attack_flow": None,
    })

    while not stop_event.is_set():
        stop_event.wait(PREDICTION_INTERVAL)
        if stop_event.is_set():
            break

        start_proc = time.time()

        active_flows, stale_keys = [], []
        with flow_lock:
            if not flow_table:
                continue
            now = time.time()
            for key, flow in flow_table.items():
                if _should_monitor(flow):
                    active_flows.append((key, flow))

                age = now - flow.start_time
                if age > STALE_FLOW_TIMEOUT or flow.is_finished:
                    stale_keys.append(key)

            active_keys = {key for key, _ in active_flows}
            for k in stale_keys:
                if k not in active_keys:
                    del flow_table[k]

        if not active_flows:
            continue

        feature_list = []
        valid_flows = []

        for key, flow in active_flows:
            try:
                features = build_features_from_flow(flow)
                feature_list.append(features)
                valid_flows.append(flow)
            except Exception as exc:
                logger.error("Feature extraction error for flow %s: %s", key, exc)
                continue

        if not feature_list:
            continue

        try:
            attack_detected = False
            max_conf = 0.0
            attack_info = None
            if LIVE_FLOW_ALERT_THRESHOLD and len(active_flows) >= LIVE_FLOW_ALERT_THRESHOLD:
                attack_detected = True
                max_conf = 1.0
                attack_info = _flow_info(active_flows[0][1], max_conf, "flow_count")
                detection_history.append(_history_event(active_flows[0][1], max_conf))

            results = model_service.predict_many(feature_list)
            for flow, result in zip(valid_flows, results):
                pred = result["prediction_label"]
                conf = result["confidence"] or 0.0
                thresh = (
                    REQ_CONFIDENCE_THRESHOLD
                    if flow.state in INCOMPLETE_STATES
                    else CONFIDENCE_THRESHOLD
                )

                if pred == 1 and conf >= thresh:
                    attack_detected = True
                    if conf > max_conf:
                        max_conf = conf
                        attack_info = _flow_info(flow, conf, "model")

                    detection_history.append(_history_event(flow, conf))

            ts = time.strftime("%H:%M:%S")
            proc_time = time.time() - start_proc

            if attack_detected:
                latest_prediction.update({
                    "status": "ATTACK",
                    "prediction": 1,
                    "confidence": round(max_conf, 4),
                    "timestamp": time.time(),
                    "active_flows": len(active_flows),
                    "attacker_ip": attack_info["src"],
                    "target_port": attack_info["dport"],
                    "attack_flow": attack_info,
                })
                logger.warning(
                    "[%s] ATTACK conf=%0.0f%% attacker_ip=%s target=%s:%s detector=%s flows=%s time=%0.2fs",
                    ts,
                    max_conf * 100,
                    attack_info["src"],
                    attack_info["dst"],
                    attack_info["dport"],
                    attack_info["detector"],
                    len(active_flows),
                    proc_time,
                )
            else:
                latest_prediction.update({
                    "status": "OK",
                    "prediction": 0,
                    "confidence": 1.0,
                    "timestamp": time.time(),
                    "active_flows": len(active_flows),
                    "attacker_ip": None,
                    "target_port": None,
                    "attack_flow": None,
                })
                logger.info("[%s] OK flows=%s time=%0.2fs", ts, len(active_flows), proc_time)

        except Exception as e:
            logger.error(f"Batch prediction error: {e}")

        with flow_lock:
            for key, flow in active_flows:
                if flow.is_finished and key in flow_table:
                    del flow_table[key]
