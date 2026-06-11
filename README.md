# 🛡️ NIDS Simulation API v2.0 (Random Forest)

Sistem Deteksi Intrusi Jaringan (NIDS) berbasis Machine Learning yang menggunakan algoritma **Random Forest** dengan dataset **UNSW-NB15**. API ini mampu melakukan sniffing paket data secara *real-time*, membangun fitur per-flow, dan memberikan prediksi apakah lalu lintas jaringan tersebut merupakan serangan (**ATTACK**) atau normal (**OK**) beserta confidence score.

## 🚀 Fitur Utama
- **Real-time Flow-based Sniffing**: Menangkap paket data dari semua interface aktif dan mengelompokkannya per-flow (src:sport → dst:dport) menggunakan Scapy.
- **192 Feature Mapping**: Memetakan 30+ fitur penting UNSW-NB15 termasuk bidirectional metrics (dbytes, dpkts, dload), TCP timing (tcprtt, synack, ackdat), connection tracking (ct_*), dan jitter/loss.
- **Confidence Score**: Setiap prediksi disertai probability score dari model.
- **REST API**: Dibangun dengan FastAPI untuk integrasi yang mudah.
- **Detection History**: Menyimpan riwayat 200 deteksi terakhir.
- **Flow Monitoring**: Endpoint untuk melihat active flows secara real-time.

## 📥 Download Model
Karena ukuran model (**156MB**) melebihi limit GitHub, silakan unduh file `rf_model.pkl` melalui tautan berikut dan letakkan di root directory project:

> [!IMPORTANT]
> **[Download rf_model.pkl (Google Drive)](https://drive.google.com/drive/folders/1nAIYNhCGZwIwnHrAoUbhqdOcxIlTUzDp?usp=sharing)**

## 🛠️ Persyaratan Sistem
- Python 3.10+
- Root/Sudo Privileges (untuk sniffing paket data)
- Dependency Python di `requirements.txt`

## 📂 Struktur Proyek
| File | Deskripsi |
|------|-----------|
| `main.py` | Application entry point (FastAPI lifespan + background threads) |
| `app/` | Core package containing logic, API, and services |
| `requirements.txt` | Reproducible Python dependency list |
| `tests/functional/test_api_validation.py` | Automated validation test for `/inspect` and `/status` |
| `tests/functional/test_attack_profiles.py` | Automated regression test for calibrated attack/normal profiles |
| `tests/functional/test_attacks.py` | Test suite: 10 calibrated profiles (attack + normal) |
| `tests/integration/test_nmap.py` | Automated nmap scan detection testing |
| `tests/functional/test_client.py` | API endpoint functional tests |
| `tests/scripts/simulate_attack.py` | Manual attack simulation utility |
| `rf_model.pkl` | Model Random Forest (UNSW-NB15) |

## 🏁 Cara Menjalankan

### 1. Install Dependency
```bash
python -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. Menjalankan Server
```bash
sudo ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

`python main.py` juga masih bisa dipakai untuk menjalankan server lokal.

### 3. Konfigurasi Runtime

| Env Var | Default | Deskripsi |
| --- | --- | --- |
| `NIDS_MODEL_PATH` | `<project>/rf_model.pkl` | Lokasi file model. |
| `NIDS_API_TOKEN` | kosong | Jika diisi, endpoint sensitif wajib memakai `Authorization: Bearer <token>` atau `X-API-Token`. |
| `NIDS_ENABLE_SNIFFER` | `true` | Set `false` untuk menjalankan API tanpa sniffing paket. |
| `NIDS_INTERFACES` | auto-detect | Comma-separated interface, contoh `eth0,ens3`. |
| `NIDS_MONITORING_MODE` | `inbound` | `inbound` untuk trafik menuju local IP, `all` untuk semua flow non-whitelist. |
| `NIDS_WHITELIST_IPS` | kosong | Comma-separated IP sumber yang diabaikan. |
| `NIDS_MIN_SRC_PACKETS` | `1` | Minimum source packet sebelum flow diprediksi. |
| `NIDS_MAX_INSPECT_FEATURES` | `250` | Batas jumlah fitur dalam satu payload `/inspect`. |
| `NIDS_CONFIDENCE_THRESHOLD` | `0.80` | Threshold confidence untuk flow established. |
| `NIDS_REQ_CONFIDENCE_THRESHOLD` | `0.80` | Threshold confidence untuk state `REQ`/`INT`. |
| `NIDS_PREDICTION_INTERVAL` | `1.0` | Interval prediksi dalam detik. |
| `NIDS_STALE_FLOW_TIMEOUT` | `30` | Timeout cleanup flow dalam detik. |
| `NIDS_LOOKBACK_WINDOW` | `100` | Lookback window untuk fitur `ct_*`. |
| `NIDS_ENABLE_AUTO_BLOCK` | `true` | Jika attack terdeteksi, IP sumber dimasukkan ke blocklist. |
| `NIDS_BLOCK_MODE` | `internal` | `internal` menolak request HTTP ke API; `iptables` juga menambahkan rule DROP. |
| `NIDS_BLOCKLIST_PATH` | `<project>/blocked_ips.json` | Lokasi persistensi blocklist. |

Contoh:
```bash
sudo NIDS_API_TOKEN="$(openssl rand -hex 32)" NIDS_INTERFACES=eth0 NIDS_WHITELIST_IPS=8.8.8.8 ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Untuk systemd, simpan konfigurasi production di `/etc/nids-api.env`:

```bash
NIDS_API_TOKEN=isi-token-panjang
NIDS_INTERFACES=eth0
NIDS_WHITELIST_IPS=IP_ADMIN_LU
NIDS_ENABLE_AUTO_BLOCK=true
NIDS_BLOCK_MODE=internal
```

Gunakan `NIDS_BLOCK_MODE=iptables` hanya kalau rule firewall otomatis memang diinginkan dan sudah dites di console server.

### 4. Testing

#### Automated Validation Test
```bash
NIDS_ENABLE_SNIFFER=false ./venv/bin/python -m unittest discover -v
```

#### Functional Testing (Accuracy & Endpoints)
```bash
NIDS_API_URL=http://127.0.0.1:8000 ./venv/bin/python tests/functional/test_attacks.py
NIDS_API_URL=http://127.0.0.1:8000 ./venv/bin/python tests/functional/test_client.py
```

#### Integration Testing (Nmap)
```bash
sudo ./venv/bin/python tests/integration/test_nmap.py
```

#### Manual Simulation
```bash
python tests/scripts/simulate_attack.py
```

## 📡 Endpoint API

| Method | Endpoint | Deskripsi |
| --- | --- | --- |
| `GET` | `/` | Informasi dasar API dan metadata model. |
| `GET` | `/status` | Hasil deteksi terbaru dari trafik *real-time* (+ confidence) dan status sniffer. |
| `GET` | `/healthz` | Health check ringan untuk service monitor/load balancer. |
| `POST` | `/inspect` | Prediksi manual berdasarkan input fitur (JSON). Response: prediction, status, confidence, probabilities. |
| `GET` | `/history` | 50 deteksi terakhir dengan timestamp dan flow info. |
| `GET` | `/flows` | Active flows yang sedang dimonitor (src, dst, proto, state, packet counts). |
| `GET` | `/features` | Daftar 192 fitur, model metadata, dan top 20 feature importances. |
| `GET` | `/config` | Konfigurasi detector aktif. |
| `GET` | `/blocks` | Daftar IP yang masuk blocklist internal/firewall. |
| `GET` | `/debug` | Feature values dan raw prediction untuk active flows. |

Jika `NIDS_API_TOKEN` diisi, endpoint selain `/`, `/status`, `/healthz`, `/docs`, dan `/openapi.json` memerlukan token:

```bash
curl -H "Authorization: Bearer $NIDS_API_TOKEN" http://127.0.0.1:8000/blocks
```

## 🧪 Hasil Test

### Attack Pattern Test (`test_attacks.py`)
```
Overall: 10/10 (100%)

🚨 Attack Detection (TPR): 6/6 (100%)
  ✅ DoS/DDoS Flood: ATTACK (0.53)
  ✅ SYN Flood: ATTACK (0.53)
  ✅ Port Scan: ATTACK (0.70)
  ✅ Exploit Attempt: ATTACK (0.68)
  ✅ Backdoor / Reverse Shell: ATTACK (0.73)
  ✅ Fuzzing / Analysis: ATTACK (0.69)

✅ Normal Traffic (TNR): 4/4 (100%)
  ✅ Normal HTTP: OK (0.67)
  ✅ Normal DNS: OK (0.58)
  ✅ Normal HTTPS: OK (0.63)
  ✅ Idle Connection: OK (0.79)

False Positive Rate: 0%
False Negative Rate: 0%
```

## ⚠️ Catatan Penting
- **InconsistentVersionWarning**: Model dilatih dengan scikit-learn 1.6.1. Jika muncul warning saat unpickle, pastikan versi kompatibel.
- **Network Interface**: Sniffer otomatis mendeteksi semua interface aktif (lo, eth0, wlan0, dll).
- **Model Behavior**: Model UNSW-NB15 mempelajari pattern dari dataset spesifik. Fitur yang sparse (sedikit yang diisi) cenderung diprediksi normal, sedangkan fitur yang banyak diisi (terutama bidirectional + ct_*) cenderung attack.
- **Input Validation**: Endpoint `/inspect` menolak nama fitur yang tidak ada di model supaya typo tidak diam-diam berubah menjadi nilai `0.0`.
- **Sudo Requirement**: Sniffing real-time membutuhkan root access. Tanpa sudo, jalankan dengan `NIDS_ENABLE_SNIFFER=false` untuk memakai endpoint API seperti `/inspect`.

---
*Dibuat untuk keperluan penelitian simulasi deteksi intrusi jaringan. v2.0 — Enhanced Flow-based Feature Engineering.*
