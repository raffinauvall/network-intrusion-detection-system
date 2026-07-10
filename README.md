# UNSW-NB15 Random Forest IDS API

FastAPI prototype for serving a saved scikit-learn Random Forest pipeline.
The API accepts one raw UNSW-NB15-derived traffic feature record as JSON and
returns `Normal` or `Attack`.

The primary supported flow is still JSON payload -> model pipeline -> response.
Optional Scapy live sniffing can build prototype flow features, but it is not
proof that UNSW-NB15 evaluation results transfer directly to live traffic. Auto
blocking is disabled by default.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The bundled model was trained with scikit-learn 1.6.1, so `requirements.txt`
pins that version to avoid pickle incompatibility. Use a Python version
supported by scikit-learn 1.6.1; this project was not verified on Python 3.14.

## Model And Fixtures

Place the trusted local model bundle here:

```text
models/random_forest_ids_pipeline.pkl
```

Place sample payloads here:

```text
tests/fixtures/sample_normal.json
tests/fixtures/sample_attack.json
```

The model path can be overridden:

```bash
MODEL_PATH=models/random_forest_ids_pipeline.pkl
```

## Run

```bash
uvicorn app.main:app --reload
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

## Predict

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_normal.json
```

Response shape:

```json
{
  "prediction": "Attack",
  "prediction_label": 1,
  "confidence": 0.9876,
  "probabilities": {
    "Normal": 0.0124,
    "Attack": 0.9876
  }
}
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | API and model readiness |
| `GET` | `/model-info` | Safe model metadata |
| `POST` | `/predict` | Predict one raw traffic-feature record |
| `GET` | `/status` | Latest optional live-sniffer prediction state |
| `GET` | `/flows` | Current tracked live flows |
| `GET` | `/history` | Recent live prototype attack events |

## Optional Live Sniffing

Live sniffing is off unless enabled:

```bash
NIDS_ENABLE_SNIFFER=true uvicorn app.main:app --reload
```

For local attack simulation against `127.0.0.1`, also allow loopback flows:

```bash
sudo NIDS_ENABLE_SNIFFER=true NIDS_MONITOR_LOOPBACK=true .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Depending on the interface and OS permissions, Scapy may require root:

```bash
sudo NIDS_ENABLE_SNIFFER=true .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The sniffer tracks flows and emits the same 42 raw fields used by `/predict`.
It does not manually one-hot encode `proto`, `service`, or `state`; the saved
sklearn pipeline owns preprocessing.

For lab demos, live monitoring also marks `ATTACK` when active flow count
reaches `NIDS_LIVE_FLOW_ALERT_THRESHOLD` (default `100`). Set it to `0` to
disable that prototype volume alert.

## Test

```bash
pytest -q
```

The smoke tests validate the API contract and response shape. They do not
assert that the sample normal payload must predict `Normal` or that the sample
attack payload must predict `Attack`; that should be checked against the
official UNSW-NB15 test evaluation from the training notebook.

## Limitations

- `/predict` uses request payloads.
- Live sniffing is prototype feature extraction only.
- No automatic firewall blocking or active mitigation by default.
- Not validated as production real-time packet detection.
- Model performance must be evaluated with the official UNSW-NB15 testing data,
  not from API smoke-test payloads.
