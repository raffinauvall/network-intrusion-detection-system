# 🛡️ NIDS Simulation API v2.0 (Random Forest)

Sistem Deteksi Intrusi Jaringan (NIDS) berbasis Machine Learning yang menggunakan algoritma **Random Forest** dengan dataset **UNSW-NB15**. API ini mampu melakukan sniffing paket data secara *real-time*, membangun fitur per-flow, dan memberikan prediksi apakah lalu lintas jaringan tersebut merupakan serangan (**ATTACK**) atau normal (**OK**) beserta confidence score.

## 🚀 Fitur Utama
- **Real-time Flow-based Sniffing**: Menangkap paket data dari semua interface aktif dan mengelompokkannya per-flow (src:sport → dst:dport) menggunakan Scapy.
- **192 Feature Mapping**: Memetakan 30+ fitur penting UNSW-NB15 termasuk bidirectional metrics (dbytes, dpkts, dload), TCP timing (tcprtt, synack, ackdat), connection tracking (ct_*), dan jitter/loss.
- **Confidence Score**: Setiap prediksi disertai probability score dari model.
- **REST API**: Dibangun dengan FastAPI v2.0 untuk integrasi yang mudah.
- **Detection History**: Menyimpan riwayat 200 deteksi terakhir.
- **Flow Monitoring**: Endpoint untuk melihat active flows secara real-time.

## 📥 Download Model
Karena ukuran model (**156MB**) melebihi limit GitHub, silakan unduh file `rf_model.pkl` melalui tautan berikut dan letakkan di root directory project:

> [!IMPORTANT]
> **[Download rf_model.pkl (Google Drive)](https://drive.google.com/drive/folders/1nAIYNhCGZwIwnHrAoUbhqdOcxIlTUzDp?usp=sharing)**

## 🛠️ Persyaratan Sistem
- Python 3.10+
- Root/Sudo Privileges (untuk sniffing paket data)
- Library: `fastapi`, `uvicorn`, `scapy`, `joblib`, `scikit-learn`, `pandas`, `netifaces`

## 📂 Struktur Proyek
| File | Deskripsi |
|------|-----------|
| `main.py` | Application Entry Point (FastAPI + Background Threads) |
| `app/` | Core package containing logic, API, and services |
| `tests/functional/test_attacks.py` | Test suite: 10 calibrated profiles (attack + normal) |
| `tests/integration/test_nmap.py` | Automated nmap scan detection testing |
| `tests/functional/test_client.py` | API endpoint functional tests |
| `tests/scripts/simulate_attack.py` | Manual attack simulation utility |
| `rf_model.pkl` | Model Random Forest (UNSW-NB15) |

## 🏁 Cara Menjalankan

### 1. Menjalankan Server
```bash
sudo ./venv/bin/python main.py
```

### 2. Testing

#### Functional Testing (Accuracy & Endpoints)
```bash
python tests/functional/test_attacks.py
python tests/functional/test_client.py
```

#### Integration Testing (Nmap)
```bash
sudo python tests/integration/test_nmap.py
```

#### Manual Simulation
```bash
python tests/scripts/simulate_attack.py
```

## 📡 Endpoint API

| Method | Endpoint | Deskripsi |
| --- | --- | --- |
| `GET` | `/` | Informasi dasar API dan metadata model. |
| `GET` | `/status` | Hasil deteksi terbaru dari trafik *real-time* (+ confidence). |
| `POST` | `/inspect` | Prediksi manual berdasarkan input fitur (JSON). Response: prediction, status, confidence, probabilities. |
| `GET` | `/history` | 50 deteksi terakhir dengan timestamp dan flow info. |
| `GET` | `/flows` | Active flows yang sedang dimonitor (src, dst, proto, state, packet counts). |
| `GET` | `/features` | Daftar 192 fitur, model metadata, dan top 20 feature importances. |

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
- **Sudo Requirement**: Sniffing real-time membutuhkan root access. Tanpa sudo, hanya endpoint `/inspect` yang bisa digunakan.

---
*Dibuat untuk keperluan penelitian simulasi deteksi intrusi jaringan. v2.0 — Enhanced Flow-based Feature Engineering.*
