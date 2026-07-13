from contextlib import asynccontextmanager
import threading

from fastapi import APIRouter, FastAPI

from app.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, ENABLE_SNIFFER, logger
from app.model import model_service
from app.state import detection_history, latest_prediction, sniffer_status


router = APIRouter()


@router.get("/")
async def root():
    return {
        "message": "UNSW-NB15 realtime IDS API",
        "endpoints": ["/health", "/status", "/history"],
    }


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": model_service.model is not None,
        "model_name": "Random Forest IDS Pipeline",
    }


@router.get("/status")
async def status():
    return {**latest_prediction, "sniffer": dict(sniffer_status)}


@router.get("/history")
async def history():
    return {"total": len(detection_history), "events": list(detection_history)[-50:]}


@asynccontextmanager
async def lifespan(app: FastAPI):
    model_service.load()
    stop_event = threading.Event()
    threads = []

    if ENABLE_SNIFFER:
        from app.core.detector import monitor_loop
        from app.core.sniffer import run_sniffer

        for name, target in (
            ("nids-sniffer", run_sniffer),
            ("nids-monitor", monitor_loop),
        ):
            thread = threading.Thread(target=target, args=(stop_event,), name=name, daemon=True)
            thread.start()
            threads.append(thread)
    else:
        sniffer_status.update({
            "enabled": False,
            "status": "disabled",
            "interfaces": [],
            "error": None,
        })
        logger.info("Prototype live sniffing disabled by NIDS_ENABLE_SNIFFER.")

    try:
        yield
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_TITLE,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
