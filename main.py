from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import threading
import uvicorn
from app.api.routes import router
from app.core.detector import monitor_loop
from app.config import logger, APP_TITLE, APP_DESCRIPTION, APP_VERSION, ENABLE_SNIFFER
from app.state import sniffer_status
from app.services.auth import is_authorized, is_public_path
from app.services.blocker import is_blocked, load_blocklist


@asynccontextmanager
async def lifespan(app: FastAPI):
    stop_event = threading.Event()
    threads = []

    load_blocklist()

    if ENABLE_SNIFFER:
        from app.core.sniffer import run_sniffer

        sniffer_thread = threading.Thread(
            target=run_sniffer,
            args=(stop_event,),
            name="nids-sniffer",
            daemon=True,
        )
        sniffer_thread.start()
        threads.append(sniffer_thread)
    else:
        sniffer_status.update({
            "enabled": False,
            "status": "disabled",
            "interfaces": [],
            "error": None,
        })
        logger.info("Packet sniffer disabled by NIDS_ENABLE_SNIFFER.")

    prediction_thread = threading.Thread(
        target=monitor_loop,
        args=(stop_event,),
        name="nids-monitor",
        daemon=True,
    )
    prediction_thread.start()
    threads.append(prediction_thread)

    try:
        yield
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=2)


def create_app() -> FastAPI:
    api = FastAPI(
        title=APP_TITLE,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        lifespan=lifespan,
    )

    @api.middleware("http")
    async def production_guard_middleware(request, call_next):
        if not is_public_path(request.url.path) and not is_authorized(request):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid NIDS API token."},
            )

        client_host = request.client.host if request.client else None
        if client_host and is_blocked(client_host):
            return JSONResponse(
                status_code=403,
                content={"detail": "Source IP blocked by NIDS policy."},
            )
        return await call_next(request)

    api.include_router(router)
    return api


app = create_app()

if __name__ == "__main__":
    logger.info("Starting API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
