from contextlib import asynccontextmanager
import threading

from fastapi import FastAPI

from app.api.routes import router
from app.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, ENABLE_SNIFFER, logger
from app.state import sniffer_status
from app.services.model_service import model_service


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
