import pytest
import httpx

from app.main import app
from app.model import model_service


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def load_model():
    model_service.load()


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.anyio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "model_loaded": True,
        "model_name": "Random Forest IDS Pipeline",
    }


@pytest.mark.anyio
async def test_status(client):
    response = await client.get("/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "prediction" in data
    assert "sniffer" in data


@pytest.mark.anyio
async def test_history(client):
    response = await client.get("/history")
    assert response.status_code == 200
    assert response.json()["events"] == []
