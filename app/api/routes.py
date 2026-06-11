from fastapi import APIRouter, HTTPException
from app.api.schemas import InspectRequest
from app.state import (
    latest_prediction,
    detection_history,
    flow_table,
    flow_lock,
    sniffer_status,
)
from app.services.model_service import model_service
from app.services.blocker import list_blocks
from app.core.features import build_features_from_flow
from app.config import (
    BLOCK_MODE,
    ENABLE_AUTO_BLOCK,
    CONFIDENCE_THRESHOLD,
    MIN_SRC_PACKETS,
    MONITORING_MODE,
    PREDICTION_INTERVAL,
    REQ_CONFIDENCE_THRESHOLD,
    STALE_FLOW_TIMEOUT,
    TARGET_INTERFACES,
    WHITELIST_IPS,
)
import time

router = APIRouter()

API_ENDPOINTS = [
    "/status",
    "/healthz",
    "/inspect",
    "/history",
    "/flows",
    "/features",
    "/config",
    "/blocks",
    "/debug",
]


def _manual_attack_event(confidence: float) -> dict:
    return {
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "ATTACK",
        "confidence": round(confidence, 4),
        "flow": "manual_inspect",
        "proto": "manual",
        "spkts": 0,
        "dpkts": 0,
    }


def _format_prediction_result(pred: int, confidence: float, proba, used_features: int) -> dict:
    return {
        "prediction": pred,
        "status": "ATTACK" if pred == 1 else "OK",
        "confidence": round(confidence, 4),
        "probabilities": {
            "normal": round(float(proba[0]), 4),
            "attack": round(float(proba[1]), 4),
        },
        "used_features": used_features,
        "defaulted_features": len(model_service.features) - used_features,
    }


@router.get("/")
async def root():
    return {
        "message": "NIDS Simulation API is running",
        "version": "2.0",
        "endpoints": API_ENDPOINTS,
        "model": "Random Forest (UNSW-NB15)",
        "total_features": len(model_service.features)
    }

@router.get("/status")
async def get_status():
    return {**latest_prediction, "sniffer": dict(sniffer_status)}


@router.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "model_loaded": model_service.model is not None,
        "feature_count": len(model_service.features),
        "sniffer": dict(sniffer_status),
    }


@router.post("/inspect")
async def inspect(request: InspectRequest):
    used_features = len(request.features)
    model_features = set(model_service.features)
    unknown_features = sorted(set(request.features) - model_features)
    if unknown_features:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Unknown feature names.",
                "unknown_features": unknown_features,
            },
        )

    pred, confidence, proba = model_service.predict(request.features)
    result = _format_prediction_result(pred, confidence, proba, used_features)
    if pred == 1:
        detection_history.append(_manual_attack_event(confidence))
    return result

@router.get("/history")
async def get_history():
    return {"total": len(detection_history), "events": list(detection_history)[-50:]}

@router.get("/flows")
async def get_flows():
    with flow_lock:
        flows = [{
            "src": f.src_ip, "dst": f.dst_ip, "sport": f.sport, "dport": f.dport,
            "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.proto, str(f.proto)),
            "state": f.state, "src_packets": len(f.src_packets), "dst_packets": len(f.dst_packets),
            "duration": round(f.last_time - f.start_time, 3), "age": round(time.time() - f.start_time, 1)
        } for f in flow_table.values()]
    return {"active_flows": len(flows), "flows": flows}

@router.get("/features")
async def get_features():
    return model_service.get_metadata()


@router.get("/config")
async def get_config():
    """Return active detector tuning parameters."""
    return {
        "min_src_packets": MIN_SRC_PACKETS,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "req_confidence_threshold": REQ_CONFIDENCE_THRESHOLD,
        "prediction_interval": PREDICTION_INTERVAL,
        "stale_flow_timeout": STALE_FLOW_TIMEOUT,
        "monitoring_mode": MONITORING_MODE,
        "target_interfaces": TARGET_INTERFACES or "auto",
        "whitelist_ips": sorted(WHITELIST_IPS),
        "auto_block": ENABLE_AUTO_BLOCK,
        "block_mode": BLOCK_MODE,
    }


@router.get("/blocks")
async def get_blocks():
    return {"total": len(list_blocks()), "blocked_ips": list_blocks()}


@router.get("/debug")
async def debug_flows():
    """
    Inspect feature values and raw model predictions for every active flow.
    Useful for diagnosing false positives in real-time traffic.
    """
    results = []
    with flow_lock:
        flows_snapshot = list(flow_table.items())

    for key, flow in flows_snapshot:
        spkts = len(flow.src_packets)
        dpkts = len(flow.dst_packets)
        if spkts == 0:
            continue

        features = build_features_from_flow(flow)
        pred, confidence, proba = model_service.predict(features)

        # Only show non-zero features (keeps output readable)
        nonzero = {k: round(v, 4) for k, v in features.items() if v != 0.0}

        results.append({
            "flow":       f"{flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}",
            "proto":      {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.proto, str(flow.proto)),
            "state":      flow.state,
            "spkts":      spkts,
            "dpkts":      dpkts,
            "age_s":      round(time.time() - flow.start_time, 2),
            "prediction": "ATTACK" if pred == 1 else "OK",
            "confidence": round(confidence, 4),
            "p_normal":   round(float(proba[0]), 4),
            "p_attack":   round(float(proba[1]), 4),
            "nonzero_features": nonzero,
        })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return {"total_flows": len(results), "flows": results}
