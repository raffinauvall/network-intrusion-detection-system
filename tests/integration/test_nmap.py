#!/usr/bin/env python3
"""
test_nmap.py - Automated nmap scan testing against NIDS API.

Usage:
    sudo python test_nmap.py

This script runs various nmap scans against localhost and checks
if the NIDS model detects them as attacks.
"""
import subprocess
import requests
import time
import sys
import os
import shlex

BASE_URL = os.environ.get("NIDS_API_URL", "http://127.0.0.1:8000")
TARGET_HOST = os.environ.get("NIDS_TEST_HOST", "127.0.0.1")
TARGET_PORT = os.environ.get("NIDS_TEST_PORT", "8000")
RESULTS = []


def check_api():
    """Check if the API is running."""
    try:
        res = requests.get(BASE_URL, timeout=3)
        if res.status_code == 200:
            print("✅ API is running.")
            return True
    except Exception:
        pass
    print("❌ API is not running. Start it with: sudo ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000")
    return False


def get_status():
    """Get current detection status."""
    try:
        res = requests.get(f"{BASE_URL}/status", timeout=5)
        return res.json()
    except Exception as e:
        return {"error": str(e)}


def get_history():
    """Get detection history."""
    try:
        res = requests.get(f"{BASE_URL}/history", timeout=5)
        return res.json()
    except Exception as e:
        return {"error": str(e)}


def run_nmap_scan(name, command, wait_before=2, wait_after=5):
    """
    Run an nmap scan and check if it was detected.

    Args:
        name: Descriptive name for the scan
        command: nmap command to execute
        wait_before: seconds to wait before scan (for baseline)
        wait_after: seconds to wait after scan (for detection)
    """
    print(f"\n{'='*60}")
    print(f"🔍 TEST: {name}")
    print(f"   Command: {command}")
    print(f"{'='*60}")

    # Get baseline status
    baseline = get_status()
    print(f"   Baseline status: {baseline.get('status', 'N/A')}")

    # Get history count before
    hist_before = get_history()
    events_before = hist_before.get("total", 0)

    # Wait a bit for clean baseline
    time.sleep(wait_before)

    # Run nmap scan
    print(f"   🚀 Running nmap scan...")
    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=60
        )
        nmap_output = result.stdout[-500:] if result.stdout else "No output"
        print(f"   Nmap completed. Output (last 500 chars):")
        for line in nmap_output.strip().split('\n')[-10:]:
            print(f"     | {line}")
    except subprocess.TimeoutExpired:
        print("   ⚠️ Nmap scan timed out (60s)")
    except FileNotFoundError:
        print("   ❌ nmap is not installed! Install with: sudo apt install nmap")
        return
    except Exception as e:
        print(f"   ❌ Error running nmap: {e}")
        return

    # Wait for detection
    print(f"   ⏳ Waiting {wait_after}s for detection...")
    time.sleep(wait_after)

    # Check status after scan
    status_after = get_status()
    hist_after = get_history()
    events_after = hist_after.get("total", 0)
    new_events = events_after - events_before

    detected = status_after.get("status") == "ATTACK" or new_events > 0

    result_entry = {
        "test": name,
        "command": command,
        "detected": detected,
        "status_after": status_after.get("status", "N/A"),
        "confidence": status_after.get("confidence", "N/A"),
        "new_detection_events": new_events,
    }
    RESULTS.append(result_entry)

    if detected:
        print(f"   🚨 DETECTED! Status: {status_after.get('status')}")
        print(f"   📊 Confidence: {status_after.get('confidence', 'N/A')}")
        print(f"   📝 New detection events: {new_events}")
        if status_after.get("attack_flow"):
            af = status_after["attack_flow"]
            print(f"   🔗 Attack flow: {af.get('src', '?')}:{af.get('sport', '?')} -> "
                  f"{af.get('dst', '?')}:{af.get('dport', '?')}")
    else:
        print(f"   ⚠️  NOT DETECTED. Status remains: {status_after.get('status', 'N/A')}")
        print(f"   📊 Confidence: {status_after.get('confidence', 'N/A')}")

    return detected


def print_summary():
    """Print test results summary."""
    print(f"\n\n{'='*60}")
    print(f"📋 TEST RESULTS SUMMARY")
    print(f"{'='*60}")

    detected_count = sum(1 for r in RESULTS if r["detected"])
    total = len(RESULTS)

    for r in RESULTS:
        icon = "✅" if r["detected"] else "❌"
        print(f"  {icon} {r['test']}")
        print(f"     Status: {r['status_after']} | "
              f"Confidence: {r['confidence']} | "
              f"New Events: {r['new_detection_events']}")

    print(f"\n{'='*60}")
    print(f"  Detection Rate: {detected_count}/{total} "
          f"({detected_count/total*100:.0f}%)" if total > 0 else "  No tests run")
    print(f"{'='*60}")


def main():
    print("=" * 60)
    print("🛡️  NIDS API - NMAP SCAN DETECTION TEST")
    print("=" * 60)

    if not check_api():
        sys.exit(1)

    # Check if running as root (needed for most nmap scans)
    import os
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. Some scan types may fail.")
        print("   Recommend: sudo python test_nmap.py")

    # === SCAN TESTS ===

    # 1. SYN Scan (most common, half-open)
    run_nmap_scan(
        "SYN Scan (Half-Open)",
        f"nmap -sS -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 2. Service Version Detection
    run_nmap_scan(
        "Service Version Scan",
        f"nmap -sV -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 3. TCP Connect Scan
    run_nmap_scan(
        "TCP Connect Scan",
        f"nmap -sT -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 4. Aggressive Scan (OS detection + script + version + traceroute)
    run_nmap_scan(
        "Aggressive Scan (-A)",
        f"nmap -A -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=8
    )

    # 5. Xmas Scan (FIN+PSH+URG)
    run_nmap_scan(
        "Xmas Scan",
        f"nmap -sX -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 6. FIN Scan
    run_nmap_scan(
        "FIN Scan",
        f"nmap -sF -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 7. NULL Scan
    run_nmap_scan(
        "NULL Scan",
        f"nmap -sN -p {TARGET_PORT} {TARGET_HOST}",
        wait_after=5
    )

    # 8. Multi-port scan (wider reconnaissance)
    run_nmap_scan(
        "Multi-Port Reconnaissance",
        f"nmap -sS -p 1-1024 {TARGET_HOST}",
        wait_after=8
    )

    # 9. Fast scan
    run_nmap_scan(
        "Fast Scan (-F)",
        f"nmap -sS -F {TARGET_HOST}",
        wait_after=5
    )

    # 10. Ping + port scan combo
    run_nmap_scan(
        "Ping + Port Scan",
        f"nmap -sS -sV -O -p 22,80,443,{TARGET_PORT} {TARGET_HOST}",
        wait_after=8
    )

    # Print final summary
    print_summary()

    # Show detection history
    print(f"\n📜 Full Detection History:")
    history = get_history()
    for event in history.get("events", [])[-20:]:
        print(f"  [{event.get('time_str', '?')}] "
              f"{event.get('status', '?')} | "
              f"Confidence: {event.get('confidence', '?'):.4f} | "
              f"Flow: {event.get('flow', '?')} | "
              f"Proto: {event.get('proto', '?')}")


if __name__ == "__main__":
    main()
