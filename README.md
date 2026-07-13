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

Run API biasa untuk prediksi dari JSON:

```bash
uvicorn app.main:app --reload
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

Cek API:

```bash
curl http://127.0.0.1:8000/health
```

## Struktur Project

Source utama sengaja dibuat pendek supaya mudah dijelaskan di laporan:

```text
app/
  main.py        # FastAPI app dan endpoint
  model.py       # load model dan prediksi
  schemas.py     # daftar 42 fitur, validasi request, response model
  config.py      # konfigurasi environment
  state.py       # state runtime untuk live sniffing
  network.py     # helper port, interface, jitter, loss
  blocker.py     # blocking opsional, default nonaktif
  core/
    flow.py      # representasi flow
    features.py  # ekstraksi 42 fitur dari flow live
    sniffer.py   # packet capture opsional
    detector.py  # loop deteksi live opsional
```

Alur utama penelitian: request JSON masuk ke `/predict`, divalidasi oleh
`schemas.py`, dikirim ke model di `model.py`, lalu hasil dikembalikan oleh
endpoint di `main.py`. Modul `core/` hanya dipakai jika live sniffing diaktifkan.

## Predict

Prediksi payload normal:

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_normal.json
```

Prediksi payload attack:

```bash
curl -X POST "http://127.0.0.1:8000/predict" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_attack.json
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

Live sniffing dipakai kalau mau demo traffic lokal ditangkap langsung dari
interface jaringan. Jalankan dari terminal pertama:

```bash
sudo NIDS_ENABLE_SNIFFER=true \
  NIDS_MONITOR_LOOPBACK=true \
  NIDS_LIVE_FLOW_ALERT_THRESHOLD=20 \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Kenapa pakai `sudo`: Scapy biasanya butuh permission root untuk sniff packet.
Kenapa `NIDS_MONITOR_LOOPBACK=true`: supaya traffic ke `127.0.0.1` ikut
diproses saat praktikum lokal.

Pantau status dari terminal kedua:

```bash
curl http://127.0.0.1:8000/status
curl http://127.0.0.1:8000/flows
curl http://127.0.0.1:8000/history
```

## Simulasi Serangan Lokal

Gunakan hanya ke mesin sendiri atau lab yang memang lu punya izin. Contoh di
bawah diarahkan ke `127.0.0.1`, bukan IP publik.

Pastikan live sniffing sudah hidup seperti bagian sebelumnya. Lalu dari
terminal kedua jalankan simulasi SYN flood lokal:

```bash
sudo .venv/bin/python tests/scripts/dos_simulation.py 127.0.0.1
```

Setelah itu cek hasil deteksi:

```bash
curl http://127.0.0.1:8000/status
curl http://127.0.0.1:8000/history
```

Untuk bukti laporan, simpan bagian berikut:

- screenshot terminal API saat muncul status `ATTACK`
- output `GET /status`
- output `GET /history`
- penjelasan bahwa simulasi dilakukan di loopback `127.0.0.1`

Alur demo:

```text
traffic SYN flood lokal -> sniffer Scapy -> flow_table -> ekstraksi 42 fitur
-> model Random Forest -> status ATTACK/OK -> endpoint /status dan /history
```

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
