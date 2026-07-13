import json
import sys
from pathlib import Path

import pytest
import httpx

from app.main import app
from app.schemas import FEATURE_COLUMNS
from app.model import model_service


FIXTURES = Path(__file__).parent / "fixtures"


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


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def assert_prediction_shape(data: dict) -> None:
    assert data["prediction"] in {"Normal", "Attack"}
    assert data["prediction_label"] in {0, 1}
    assert data["confidence"] is None or isinstance(data["confidence"], float)
    assert isinstance(data["probabilities"], dict)
    if data["probabilities"]:
        assert set(data["probabilities"]) <= {"Normal", "Attack"}
        assert sum(data["probabilities"].values()) == pytest.approx(1.0, abs=0.01)


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
async def test_model_info(client):
    response = await client.get("/model-info")
    data = response.json()
    assert response.status_code == 200
    assert data["feature_count"] == 42
    assert data["feature_columns"] == FEATURE_COLUMNS
    assert data["label_mapping"] == {"0": "Normal", "1": "Attack"}


@pytest.mark.anyio
async def test_predict_normal_fixture(client):
    response = await client.post("/predict", json=load_fixture("sample_normal.json"))
    assert response.status_code == 200
    assert_prediction_shape(response.json())


@pytest.mark.anyio
async def test_predict_attack_fixture(client):
    response = await client.post("/predict", json=load_fixture("sample_attack.json"))
    assert response.status_code == 200
    assert_prediction_shape(response.json())


@pytest.mark.anyio
async def test_missing_required_field_returns_validation_error(client):
    payload = load_fixture("sample_normal.json")
    payload.pop("dur")

    response = await client.post("/predict", json=payload)
    assert response.status_code == 422


@pytest.mark.anyio
async def test_unknown_field_returns_validation_error(client):
    payload = load_fixture("sample_normal.json")
    payload["proto_tcp"] = 1.0

    response = await client.post("/predict", json=payload)
    assert response.status_code == 422


@pytest.mark.anyio
async def test_prediction_api_does_not_import_legacy_packet_tools(client):
    response = await client.post("/predict", json=load_fixture("sample_normal.json"))
    assert response.status_code == 200
    assert "scapy" not in sys.modules
    assert "app.core.sniffer" not in sys.modules
