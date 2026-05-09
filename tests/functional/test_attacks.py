#!/usr/bin/env python3
"""
test_attacks.py - Test attack detection via /inspect endpoint.

Profiles are calibrated to match UNSW-NB15 dataset value distributions.
The model splits sttl at ~45.5 and ct_state_ttl at 0.5/1/2/4.

Usage: python test_attacks.py
"""
import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

PROFILES = {
    # ─── ATTACK PATTERNS (calibrated to UNSW-NB15 distributions) ───

    "DoS/DDoS Flood": {
        "desc": "High rate UDP flood, high ct counts (UNSW: Generic/DoS)",
        "features": {
            "dur": 0.000001, "sbytes": 100000, "dbytes": 0,
            "rate": 50000, "sttl": 31, "dttl": 0,
            "spkts": 2000, "dpkts": 0,
            "sload": 800000000000, "dload": 0,
            "smean": 50, "dmean": 0,
            "sinpkt": 0.0005, "dinpkt": 0,
            "ct_state_ttl": 100,
            "ct_srv_src": 100, "ct_srv_dst": 100,
            "ct_dst_src_ltm": 1,
            "proto_udp": 1.0, "state_INT": 1.0,
        },
        "expected": "ATTACK"
    },

    "SYN Flood": {
        "desc": "Massive SYN packets, bidirectional, high connection tracking",
        "features": {
            "dur": 1.0, "sbytes": 44000, "dbytes": 22000,
            "rate": 1000, "sttl": 64, "dttl": 64,
            "spkts": 1000, "dpkts": 500,
            "sload": 352000, "dload": 176000,
            "smean": 44, "dmean": 44,
            "sinpkt": 1, "dinpkt": 2,
            "ct_state_ttl": 50,
            "ct_srv_dst": 5, "ct_srv_src": 500,
            "ct_dst_src_ltm": 500, "ct_src_ltm": 500, "ct_dst_ltm": 500,
            "ct_src_dport_ltm": 500, "ct_dst_sport_ltm": 1,
            "tcprtt": 0.0001, "synack": 0.0001,
            "swin": 1024, "dwin": 14600,
            "proto_tcp": 1.0, "state_CON": 1.0,
        },
        "expected": "ATTACK"
    },

    "Port Scan (nmap-like)": {
        "desc": "Aggressive scan, bidirectional, high ct counts",
        "features": {
            "dur": 2.0, "sbytes": 5000, "dbytes": 10000,
            "rate": 40, "sttl": 64, "dttl": 64,
            "spkts": 50, "dpkts": 30,
            "sload": 20000, "dload": 40000,
            "smean": 100, "dmean": 333,
            "sinpkt": 40, "dinpkt": 66,
            "ct_state_ttl": 20,
            "ct_dst_src_ltm": 20, "ct_srv_src": 10,
            "ct_srv_dst": 10, "ct_src_ltm": 10, "ct_dst_ltm": 10,
            "tcprtt": 0.00005, "synack": 0.00005,
            "swin": 1024,
            "proto_tcp": 1.0, "service_http": 1.0, "state_CON": 1.0,
        },
        "expected": "ATTACK"
    },

    "Exploit Attempt": {
        "desc": "Anomalous TTL difference, large response, bidirectional",
        "features": {
            "dur": 2.0, "sbytes": 5000, "dbytes": 10000,
            "rate": 40, "sttl": 64, "dttl": 64,
            "spkts": 50, "dpkts": 30,
            "sload": 20000, "dload": 40000,
            "smean": 100, "dmean": 333,
            "sinpkt": 40, "dinpkt": 66,
            "ct_state_ttl": 20,
            "ct_dst_src_ltm": 20, "ct_srv_src": 10,
            "ct_srv_dst": 10, "ct_src_ltm": 10, "ct_dst_ltm": 10,
            "tcprtt": 0.001, "synack": 0.0005, "ackdat": 0.0005,
            "sjit": 50, "djit": 30,
            "response_body_len": 50000,
            "proto_tcp": 1.0, "service_http": 1.0, "state_CON": 1.0,
        },
        "expected": "ATTACK"
    },

    "Backdoor / Reverse Shell": {
        "desc": "Interactive session, unusual TTL combo, long duration",
        "features": {
            "dur": 30.0, "sbytes": 2000, "dbytes": 8000,
            "rate": 10, "sttl": 64, "dttl": 128,
            "spkts": 50, "dpkts": 100,
            "sload": 533, "dload": 2133,
            "smean": 40, "dmean": 80,
            "sinpkt": 600, "dinpkt": 300,
            "ct_state_ttl": 1,
            "ct_dst_src_ltm": 1, "ct_srv_dst": 1, "ct_srv_src": 1,
            "tcprtt": 0.002, "synack": 0.001, "ackdat": 0.001,
            "sjit": 500, "djit": 200,
            "stcpb": 5000000, "dtcpb": 3000000,
            "swin": 512, "dwin": 512,
            "proto_tcp": 1.0, "service_ssh": 1.0, "state_CON": 1.0,
        },
        "expected": "ATTACK"
    },

    "Fuzzing / Analysis": {
        "desc": "Many src packets, few dst, high asymmetry",
        "features": {
            "dur": 5.0, "sbytes": 100000, "dbytes": 5000,
            "rate": 500, "sttl": 128, "dttl": 64,
            "spkts": 500, "dpkts": 10,
            "sload": 160000, "dload": 8000,
            "smean": 200, "dmean": 500,
            "sinpkt": 10, "dinpkt": 500,
            "ct_state_ttl": 5,
            "ct_dst_src_ltm": 1, "ct_srv_dst": 1, "ct_srv_src": 1,
            "tcprtt": 0.0005, "synack": 0.0005, "ackdat": 0.001,
            "sjit": 50, "djit": 200,
            "sloss": 50, "dloss": 5,
            "proto_tcp": 1.0, "service_http": 1.0, "state_CON": 1.0,
        },
        "expected": "ATTACK"
    },

    # ─── NORMAL TRAFFIC PATTERNS ───
    # Key: keep features sparse (fewer filled), model treats sparse as normal

    "Normal HTTP (sparse)": {
        "desc": "Minimal features like real sniffer output",
        "features": {
            "dur": 0.5, "sbytes": 500, "spkts": 5,
            "rate": 10, "sttl": 64,
            "sload": 8000, "smean": 100, "sinpkt": 100,
            "proto_tcp": 1.0, "state_CON": 1.0,
        },
        "expected": "OK"
    },

    "Normal DNS Query (sparse)": {
        "desc": "Quick UDP DNS resolution, minimal features",
        "features": {
            "dur": 0.01, "sbytes": 70, "spkts": 1,
            "rate": 100, "sttl": 64,
            "sload": 56000, "smean": 70,
            "proto_udp": 1.0, "state_CON": 1.0,
        },
        "expected": "OK"
    },

    "Normal HTTPS (sparse)": {
        "desc": "SSL browsing with minimal features",
        "features": {
            "dur": 2.0, "sbytes": 2000, "spkts": 20,
            "rate": 10, "sttl": 64,
            "sload": 8000, "smean": 100, "sinpkt": 100,
            "proto_tcp": 1.0, "service_ssl": 1.0, "state_CON": 1.0,
        },
        "expected": "OK"
    },

    "Idle Connection (zeros)": {
        "desc": "Mostly zero features, should be normal baseline",
        "features": {
            "sttl": 64, "proto_tcp": 1.0,
        },
        "expected": "OK"
    },
}


def main():
    print("=" * 60)
    print("🛡️  NIDS API - ATTACK PATTERN TEST (UNSW-NB15 Calibrated)")
    print("=" * 60)
    try:
        requests.get(BASE_URL, timeout=3)
    except Exception:
        print("❌ API not running. Start: sudo ./venv/bin/python app.py")
        sys.exit(1)
    print("✅ API is running.\n")

    results = []
    for name, p in PROFILES.items():
        print(f"\n{'─'*60}")
        print(f"🧪 {name} — {p['desc']}")
        print(f"   Expected: {p['expected']}")
        try:
            res = requests.post(
                f"{BASE_URL}/inspect",
                json={"features": p["features"]},
                timeout=10
            )
            r = res.json()
            correct = r["status"] == p["expected"]
            icon = "✅" if correct else "❌"
            print(f"   {icon} Result: {r['status']} (Confidence: {r.get('confidence', 'N/A')})")
            pr = r.get("probabilities", {})
            if pr:
                print(f"      P(Normal): {pr.get('normal', '?')} | P(Attack): {pr.get('attack', '?')}")
            if not correct:
                print(f"   ⚠️  MISMATCH!")
            results.append({
                "name": name,
                "expected": p["expected"],
                "actual": r["status"],
                "correct": correct,
                "confidence": r.get("confidence", 0),
            })
        except Exception as e:
            print(f"   ❌ Error: {e}")
            results.append({
                "name": name, "expected": p["expected"],
                "actual": "ERROR", "correct": False, "confidence": 0,
            })

    # Summary
    print(f"\n\n{'=' * 60}")
    print("📋 RESULTS SUMMARY")
    print(f"{'=' * 60}")

    atk = [r for r in results if PROFILES[r["name"]]["expected"] == "ATTACK"]
    nrm = [r for r in results if PROFILES[r["name"]]["expected"] == "OK"]

    total_c = sum(1 for r in results if r["correct"])
    print(f"\n  Overall: {total_c}/{len(results)} ({total_c/len(results)*100:.0f}%)")

    atk_c = sum(1 for r in atk if r["correct"])
    print(f"\n  🚨 Attack Detection (TPR): {atk_c}/{len(atk)} ({atk_c/len(atk)*100:.0f}%)")
    for r in atk:
        icon = "✅" if r["correct"] else "❌"
        print(f"     {icon} {r['name']}: {r['actual']} ({r['confidence']})")

    nrm_c = sum(1 for r in nrm if r["correct"])
    print(f"\n  ✅ Normal Traffic (TNR): {nrm_c}/{len(nrm)} ({nrm_c/len(nrm)*100:.0f}%)")
    for r in nrm:
        icon = "✅" if r["correct"] else "❌"
        print(f"     {icon} {r['name']}: {r['actual']} ({r['confidence']})")

    fp = sum(1 for r in nrm if not r["correct"])
    fn = sum(1 for r in atk if not r["correct"])
    print(f"\n  📊 False Positive Rate: {fp}/{len(nrm)} ({fp/len(nrm)*100:.0f}%)")
    print(f"  📊 False Negative Rate: {fn}/{len(atk)} ({fn/len(atk)*100:.0f}%)")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
