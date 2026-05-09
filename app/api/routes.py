from fastapi import APIRouter
from app.api.schemas import InspectRequest
from app.state import latest_prediction, detection_history, flow_table, flow_lock
from app.services.model_service import model_service
import time

router = APIRouter()

@router.get("/")
async def root():
    return {
        "message": "NIDS Simulation API is running",
        "version": "2.0",
        "endpoints": ["/status", "/inspect", "/history", "/flows", "/features"],
        "model": "Random Forest (UNSW-NB15)",
        "total_features": len(model_service.features)
    }

@router.get("/status")
async def get_status():
    return latest_prediction

@router.post("/inspect")
async def inspect(request: InspectRequest):
    pred, confidence, proba = model_service.predict(request.features)
    result = {
        "prediction": pred,
        "status": "ATTACK" if pred == 1 else "OK",
        "confidence": round(confidence, 4),
        "probabilities": {"normal": round(float(proba[0]), 4), "attack": round(float(proba[1]), 4)}
    }
    if pred == 1:
        detection_history.append({
            "timestamp": time.time(), "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ATTACK", "confidence": confidence, "flow": "manual_inspect",
            "proto": "manual", "spkts": 0, "dpkts": 0
        })
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
