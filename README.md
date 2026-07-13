# UNSW-NB15 Realtime IDS API

FastAPI prototype untuk menjalankan deteksi intrusi realtime dari traffic yang
ditangkap Scapy. API ini tidak menerima payload prediksi manual; model hanya
dipakai oleh live sniffer untuk membaca status `OK` atau `ATTACK`.

## Struktur Project

Source utama sengaja dibuat pendek supaya mudah dijelaskan di laporan:

```text
app/
  main.py        # FastAPI app dan endpoint
  model.py       # load model dan prediksi
  schemas.py     # daftar 42 fitur input model
  config.py      # konfigurasi environment
  state.py       # state runtime untuk live sniffing
  network.py     # helper port, interface, jitter, loss
  core/
    flow.py      # representasi flow
    features.py  # ekstraksi 42 fitur dari flow live
    sniffer.py   # packet capture realtime
    detector.py  # loop deteksi live opsional
tests/
  scripts/       # script simulasi SYN flood lab
```

Alur utama penelitian: packet ditangkap `sniffer.py`, dibentuk menjadi flow,
diekstrak menjadi 42 fitur di `features.py`, diprediksi oleh model di
`model.py`, lalu status realtime dibaca dari endpoint `main.py`.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The bundled model was trained with scikit-learn 1.6.1, so `requirements.txt`
pins that version to avoid pickle incompatibility. Use a Python version
supported by scikit-learn 1.6.1; this project was not verified on Python 3.14.

## Model

Place the trusted local model bundle here:

```text
models/random_forest_ids_pipeline.pkl
```

The model path can be overridden:

```bash
MODEL_PATH=models/random_forest_ids_pipeline.pkl
```

## Run

Jalankan API dengan live sniffing aktif:

```bash
sudo NIDS_ENABLE_SNIFFER=true \
  NIDS_MONITOR_LOOPBACK=true \
  NIDS_LIVE_FLOW_ALERT_THRESHOLD=20 \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Swagger UI tetap tersedia di `http://127.0.0.1:8000/docs`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | API and model readiness |
| `GET` | `/status` | Latest live-sniffer detection state |
| `GET` | `/history` | Recent attack events |

## Realtime Sniffing

Kenapa pakai `sudo`: Scapy biasanya butuh permission root untuk sniff packet.
Kenapa `NIDS_MONITOR_LOOPBACK=true`: supaya traffic ke `127.0.0.1` ikut
diproses saat praktikum lokal.

Pantau status dari terminal kedua:

```bash
curl http://127.0.0.1:8000/status
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

Format lengkapnya:

```bash
sudo .venv/bin/python tests/scripts/dos_simulation.py <target_ip> <target_port> <jumlah_paket>
```

Contoh kalau mau menguji port SSH lokal/lab:

```bash
sudo .venv/bin/python tests/scripts/dos_simulation.py 127.0.0.1 22 5000
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

Untuk demo lab, monitoring juga menandai `ATTACK` saat jumlah flow aktif
mencapai `NIDS_LIVE_FLOW_ALERT_THRESHOLD` (default `100`). Set ke `0` kalau
mau mematikan alert berbasis jumlah flow.

## Test

```bash
pytest -q
```

The smoke tests validate the realtime API contract and live feature extraction.

## Limitations

- Live sniffing is prototype feature extraction only.
- No automatic firewall blocking or active mitigation.
- Not validated as production real-time packet detection.
- Model performance must be evaluated with the official UNSW-NB15 testing data,
  not from live demo traffic alone.
