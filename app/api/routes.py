from fastapi import APIRouter, HTTPException, Query

from app.core.features import build_features_from_flow
from app.config import LIVE_FLOW_ALERT_THRESHOLD, logger
from app.schemas.response import HealthResponse, ModelInfoResponse, PredictionResponse
from app.schemas.traffic import TrafficRecord
from app.services.model_service import model_service
from app.state import detection_history, flow_lock, flow_table, latest_prediction, sniffer_status

router = APIRouter()


@router.get("/")
async def root():
    return {
        "message": "UNSW-NB15 IDS model-serving API",
        "endpoints": ["/health", "/model-info", "/predict", "/status", "/flows", "/history", "/debug-live"],
    }


@router.get("/health", response_model=HealthResponse)
async def health():
    return {
        "status": "ok",
        "model_loaded": model_service.model is not None,
        "model_name": "Random Forest IDS Pipeline",
    }


@router.get("/status")
async def status():
    return {**latest_prediction, "sniffer": dict(sniffer_status)}


@router.get("/flows")
async def flows():
    with flow_lock:
        items = [
            {
                "src": flow.src_ip,
                "dst": flow.dst_ip,
                "sport": flow.sport,
                "dport": flow.dport,
                "proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(flow.proto, str(flow.proto)),
                "state": flow.state,
                "spkts": len(flow.src_packets),
                "dpkts": len(flow.dst_packets),
            }
            for flow in flow_table.values()
        ]
    return {"active_flows": len(items), "flows": items}


@router.get("/history")
async def history():
    return {"total": len(detection_history), "events": list(detection_history)[-50:]}


@router.get("/debug-live")
async def debug_live(limit: int = Query(default=20, ge=1, le=100)):
    rows = []
    with flow_lock:
        flows = list(flow_table.values())[:limit]

    for flow in flows:
        features = build_features_from_flow(flow)
        result = model_service.predict(features)
        rows.append({
            "flow": f"{flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}",
            "proto": features["proto"],
            "service": features["service"],
            "state": features["state"],
            "spkts": features["spkts"],
            "dpkts": features["dpkts"],
            "rate": round(features["rate"], 4),
            "prediction": result["prediction"],
            "prediction_label": result["prediction_label"],
            "confidence": result["confidence"],
            "probabilities": result["probabilities"],
        })
    return {
        "total": len(rows),
        "live_flow_alert_threshold": LIVE_FLOW_ALERT_THRESHOLD,
        "flow_count_alert": LIVE_FLOW_ALERT_THRESHOLD > 0 and len(flow_table) >= LIVE_FLOW_ALERT_THRESHOLD,
        "flows": rows,
    }


@router.get("/model-info", response_model=ModelInfoResponse)
async def model_info():
    return model_service.get_metadata()


@router.post("/predict", response_model=PredictionResponse)
async def predict(record: TrafficRecord):
    try:
        return model_service.predict(record.model_dump())
    except Exception:
        logger.exception("Model inference failed")
        raise HTTPException(status_code=500, detail="Model inference failed.")
