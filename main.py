from fastapi import FastAPI
import threading
import uvicorn
from app.api.routes import router
from app.core.sniffer import run_sniffer
from app.core.detector import monitor_loop
from app.config import logger, APP_TITLE, APP_DESCRIPTION, APP_VERSION

app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION)

# Include routes
app.include_router(router)

if __name__ == "__main__":
    # Start Sniffer Thread
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    # Start Prediction Loop Thread
    prediction_thread = threading.Thread(target=monitor_loop, daemon=True)
    prediction_thread.start()

    # Run API
    logger.info("Starting API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
