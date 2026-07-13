"""Experimental legacy blocking helpers; unused by the supported prediction API."""

import ipaddress
import json
import subprocess
import time

from app.config import BLOCK_MODE, BLOCKLIST_PATH, BLOCK_REASON, ENABLE_AUTO_BLOCK, WHITELIST_IPS, logger
from app.state import blocked_ips, blocked_ips_lock


def save_blocklist() -> None:
    with blocked_ips_lock:
        records = list(blocked_ips.values())

    try:
        BLOCKLIST_PATH.write_text(json.dumps({"blocked_ips": records}, indent=2))
    except Exception as exc:
        logger.warning("Failed to save blocklist %s: %s", BLOCKLIST_PATH, exc)


def _is_blockable_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if ip in WHITELIST_IPS:
        return False
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        return False
    return True


def _iptables_drop_source(ip: str) -> tuple[bool, str | None]:
    check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
    add_cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]

    try:
        check = subprocess.run(check_cmd, capture_output=True, text=True, timeout=2)
    except subprocess.TimeoutExpired:
        return False, "iptables check timed out"

    if check.returncode == 0:
        return True, None

    try:
        add = subprocess.run(add_cmd, capture_output=True, text=True, timeout=2)
    except subprocess.TimeoutExpired:
        return False, "iptables add timed out"

    if add.returncode == 0:
        return True, None
    return False, (add.stderr or add.stdout or "iptables command failed").strip()


def block_ip(ip: str, reason: str = BLOCK_REASON, confidence: float | None = None) -> dict:
    if not ENABLE_AUTO_BLOCK:
        return {"blocked": False, "mode": BLOCK_MODE, "error": "auto_block_disabled"}

    if not _is_blockable_ip(ip):
        return {"blocked": False, "mode": BLOCK_MODE, "error": "ip_not_blockable"}

    now = time.time()
    with blocked_ips_lock:
        existing = blocked_ips.get(ip)
        if existing:
            existing["last_seen"] = now
            existing["hits"] += 1
            mode = existing["mode"]
            already_blocked = True
            record = None
        else:
            record = {
                "ip": ip,
                "reason": reason,
                "confidence": round(confidence, 4) if confidence is not None else None,
                "mode": BLOCK_MODE,
                "first_seen": now,
                "last_seen": now,
                "hits": 1,
                "firewall_applied": False,
                "error": None,
            }

            if BLOCK_MODE == "iptables":
                applied, error = _iptables_drop_source(ip)
                record["firewall_applied"] = applied
                record["error"] = error
            elif BLOCK_MODE != "internal":
                record["error"] = f"unsupported_block_mode:{BLOCK_MODE}"

            blocked_ips[ip] = record
            mode = BLOCK_MODE
            already_blocked = False

    save_blocklist()

    if already_blocked:
        return {"blocked": True, "mode": mode, "already_blocked": True}

    if record["error"]:
        logger.warning("Blocked %s internally, firewall mode issue: %s", ip, record["error"])
    else:
        logger.warning("Blocked %s via %s mode", ip, BLOCK_MODE)

    return {"blocked": True, "mode": BLOCK_MODE, "firewall_applied": record["firewall_applied"]}
