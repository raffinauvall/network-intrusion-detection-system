#!/usr/bin/env python3
"""
client.py - Test client for NIDS API endpoints.
Usage: python client.py
"""
import requests
import os

BASE_URL = os.environ.get("NIDS_API_URL", "http://127.0.0.1:8000")

def test_root():
    print("\n--- Root Endpoint ---")
    res = requests.get(BASE_URL)
    data = res.json()
    print(f"Message: {data['message']}")
    print(f"Version: {data.get('version', 'N/A')}")
    print(f"Endpoints: {data.get('endpoints', [])}")
    print(f"Total Features: {data.get('total_features', 'N/A')}")

def test_status():
    print("\n--- Real-time Status ---")
    res = requests.get(f"{BASE_URL}/status")
    data = res.json()
    print(f"Status: {data.get('status', 'N/A')}")
    print(f"Prediction: {data.get('prediction', 'N/A')}")
    print(f"Confidence: {data.get('confidence', 'N/A')}")
    print(f"Active Flows: {data.get('active_flows', 'N/A')}")
    sniffer = data.get("sniffer", {})
    if sniffer:
        print(f"Sniffer: {sniffer.get('status', 'N/A')}")
    if data.get("attack_flow"):
        af = data["attack_flow"]
        print(f"Attack Flow: {af['src']}:{af['sport']} -> {af['dst']}:{af['dport']}")

def test_inspect():
    print("\n--- Manual Inspection ---")
    # Sparse normal HTTP baseline.
    features = {
        "dur": 0.5,
        "sbytes": 500,
        "spkts": 5,
        "rate": 10,
        "sttl": 64,
        "sload": 8000,
        "smean": 100,
        "sinpkt": 100,
        "proto_tcp": 1.0,
        "state_CON": 1.0,
    }
    res = requests.post(f"{BASE_URL}/inspect", json={"features": features})
    data = res.json()
    print(f"Status: {data['status']}")
    print(f"Confidence: {data.get('confidence', 'N/A')}")
    proba = data.get("probabilities", {})
    if proba:
        print(f"P(Normal): {proba.get('normal')} | P(Attack): {proba.get('attack')}")

def test_history():
    print("\n--- Detection History ---")
    res = requests.get(f"{BASE_URL}/history")
    data = res.json()
    print(f"Total Events: {data.get('total', 0)}")
    events = data.get("events", [])[-5:]
    for ev in events:
        print(f"  [{ev.get('time_str','?')}] {ev.get('status','?')} | "
              f"Conf: {ev.get('confidence',0):.4f} | {ev.get('flow','?')}")

def test_flows():
    print("\n--- Active Flows ---")
    res = requests.get(f"{BASE_URL}/flows")
    data = res.json()
    print(f"Active Flows: {data.get('active_flows', 0)}")
    for f in data.get("flows", [])[:10]:
        print(f"  {f['src']}:{f['sport']} -> {f['dst']}:{f['dport']} "
              f"[{f['proto']}] State={f['state']} "
              f"SrcPkts={f['src_packets']} DstPkts={f['dst_packets']} "
              f"Age={f['age']}s")

def test_features():
    print("\n--- Model Features Info ---")
    res = requests.get(f"{BASE_URL}/features")
    data = res.json()
    print(f"Total Features: {data.get('total_features', 'N/A')}")
    print(f"Model: {data.get('model_type', 'N/A')}")
    print(f"Estimators: {data.get('n_estimators', 'N/A')}")
    print(f"Top 10 Important Features:")
    for f in data.get("top_20_features", [])[:10]:
        print(f"  - {f['name']}: {f['importance']:.6f}")

if __name__ == "__main__":
    print("=" * 50)
    print("🛡️  NIDS API Client v2.0")
    print("=" * 50)

    try:
        test_root()
        test_status()
        test_inspect()
        test_history()
        test_flows()
        test_features()
    except requests.ConnectionError:
        print("❌ Cannot connect to API. Start: sudo ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000")
    except Exception as e:
        print(f"❌ Error: {e}")

    print(f"\n{'='*50}")
    print("Done!")
