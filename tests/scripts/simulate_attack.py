#!/usr/bin/env python3
"""
simulate_attack.py - Send various attack simulations to NIDS API.
Usage: python simulate_attack.py
"""
import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def send_attack(name, description, features):
    """Send attack simulation and display results."""
    print(f"\n{'─'*50}")
    print(f"🚀 {name}")
    print(f"   {description}")

    try:
        res = requests.post(f"{BASE_URL}/inspect", json={"features": features}, timeout=10)
        result = res.json()

        status = result["status"]
        confidence = result.get("confidence", "N/A")
        proba = result.get("probabilities", {})

        if status == "ATTACK":
            print(f"   🚨 ATTACK DETECTED! Confidence: {confidence}")
        else:
            print(f"   ✅ Status: OK | Confidence: {confidence}")

        if proba:
            print(f"   📊 P(Normal)={proba.get('normal','?')} | P(Attack)={proba.get('attack','?')}")

    except Exception as e:
        print(f"   ❌ Error: {e}")


def main():
    print("=" * 50)
    print("🛡️  NIDS Attack Simulator v2.0")
    print("=" * 50)

    try:
        r = requests.get(BASE_URL, timeout=3)
        print(f"✅ Connected: {r.json()['message']}")
    except Exception:
        print("❌ API not running. Start: sudo ./venv/bin/python app.py")
        sys.exit(1)

    # 1. DoS/DDoS
    send_attack(
        "DoS/DDoS Attack",
        "High rate flood with massive bytes",
        {
            "dur": 0.0001, "sbytes": 1500000, "dbytes": 0,
            "rate": 100000, "sttl": 255, "dttl": 0,
            "spkts": 5000, "dpkts": 0,
            "sload": 50000000, "dload": 0,
            "smean": 300, "dmean": 0,
            "sinpkt": 0.001, "dinpkt": 0,
            "ct_state_ttl": 1, "ct_dst_src_ltm": 1,
            "proto_udp": 1.0, "state_INT": 1.0,
        }
    )

    # 2. SYN Flood
    send_attack(
        "SYN Flood Attack",
        "Massive half-open connections, bidirectional",
        {
            "dur": 1.0, "sbytes": 44000, "dbytes": 22000,
            "rate": 1000, "sttl": 64, "dttl": 64,
            "spkts": 1000, "dpkts": 500,
            "sload": 352000, "dload": 176000,
            "smean": 44, "dmean": 44,
            "sinpkt": 1, "dinpkt": 2,
            "ct_state_ttl": 50, "ct_srv_dst": 5, "ct_srv_src": 500,
            "ct_dst_src_ltm": 500, "ct_src_ltm": 500, "ct_dst_ltm": 500,
            "ct_src_dport_ltm": 500,
            "tcprtt": 0.0001, "synack": 0.0001,
            "swin": 1024, "dwin": 14600,
            "proto_tcp": 1.0, "state_CON": 1.0,
        }
    )

    # 3. Port Scan
    send_attack(
        "Port Scan (Recon)",
        "Aggressive nmap-like scan with bidirectional traffic",
        {
            "dur": 2.0, "sbytes": 5000, "dbytes": 10000,
            "rate": 40, "sttl": 64, "dttl": 64,
            "spkts": 50, "dpkts": 30,
            "sload": 20000, "dload": 40000,
            "smean": 100, "dmean": 333,
            "sinpkt": 40, "dinpkt": 66,
            "ct_state_ttl": 20, "ct_dst_src_ltm": 20,
            "ct_srv_src": 10, "ct_srv_dst": 10,
            "tcprtt": 0.00005, "synack": 0.00005,
            "swin": 1024,
            "proto_tcp": 1.0, "service_http": 1.0, "state_CON": 1.0,
        }
    )

    # 4. Normal Traffic (should be OK) — sparse features
    send_attack(
        "Normal HTTP Traffic (Baseline)",
        "Sparse features like real sniffer — should NOT trigger",
        {
            "dur": 0.5, "sbytes": 500, "spkts": 5,
            "rate": 10, "sttl": 64,
            "sload": 8000, "smean": 100, "sinpkt": 100,
            "proto_tcp": 1.0, "state_CON": 1.0,
        }
    )

    # 5. Check real-time status
    print(f"\n{'─'*50}")
    print("📡 Real-time Sniffer Status:")
    try:
        status = requests.get(f"{BASE_URL}/status", timeout=5).json()
        print(f"   Status: {status.get('status', 'N/A')}")
        print(f"   Confidence: {status.get('confidence', 'N/A')}")
        print(f"   Active Flows: {status.get('active_flows', 'N/A')}")
    except Exception as e:
        print(f"   Error: {e}")

    # 6. Check history
    print(f"\n📜 Detection History:")
    try:
        hist = requests.get(f"{BASE_URL}/history", timeout=5).json()
        events = hist.get("events", [])[-10:]
        if events:
            for ev in events:
                print(f"   [{ev.get('time_str','?')}] {ev.get('status','?')} | "
                      f"Conf: {ev.get('confidence',0):.4f} | {ev.get('flow','?')}")
        else:
            print("   No detection events yet.")
    except Exception as e:
        print(f"   Error: {e}")

    print(f"\n{'='*50}")
    print("Done!")


if __name__ == "__main__":
    main()
