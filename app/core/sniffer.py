import threading
import time
from scapy.all import sniff, IP, TCP
from app.state import (
    flow_table,
    flow_lock,
    connection_log,
    connection_log_lock,
    sniffer_status,
)
from app.core.flow import FlowRecord
from app.network import get_service, get_active_interfaces
from app.config import logger, TARGET_INTERFACES


def get_tcp_flags_str(pkt):
    return str(pkt[TCP].flags) if TCP in pkt else ""


def ttl_bucket(ttl: int) -> int:
    """Map raw TTL to OS-type bucket (matching UNSW-NB15 methodology)."""
    if ttl <= 64: return 64
    if ttl <= 128: return 128
    return 255


def handle_packet(pkt):
    if IP not in pkt:
        return

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    proto    = pkt[IP].proto
    ttl      = pkt[IP].ttl
    pkt_size = len(pkt)
    pkt_time = time.time()

    sport   = pkt.sport if hasattr(pkt, 'sport') else 0
    dport   = pkt.dport if hasattr(pkt, 'dport') else 0
    flags   = get_tcp_flags_str(pkt)
    tcp_seq = pkt[TCP].seq    if TCP in pkt else 0
    tcp_win = pkt[TCP].window if TCP in pkt else 0

    fwd_key = (src_ip, sport, dst_ip, dport)
    rev_key = (dst_ip, dport, src_ip, sport)

    with flow_lock:
        if fwd_key in flow_table:
            flow_table[fwd_key].add_src_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow_table[fwd_key].update_state(flags)

        elif rev_key in flow_table:
            flow_table[rev_key].add_dst_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow_table[rev_key].update_state(flags)

        else:
            # New flow — create and log it
            flow = FlowRecord(src_ip, dst_ip, sport, dport, proto)
            flow.add_src_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow.update_state(flags)
            flow_table[fwd_key] = flow

            # Log with TTL bucket + initial state for ct_state_ttl calculation
            service = get_service(dport)
            with connection_log_lock:
                connection_log.append({
                    "time":       pkt_time,
                    "src_ip":     src_ip,
                    "dst_ip":     dst_ip,
                    "sport":      sport,
                    "dport":      dport,
                    "service":    service,
                    "ttl_bucket": ttl_bucket(ttl),
                    "state":      flow.state,
                })


def run_sniffer(stop_event: threading.Event | None = None):
    # Use explicitly configured interfaces, or auto-detect if not set
    interfaces = TARGET_INTERFACES if TARGET_INTERFACES else get_active_interfaces()
    stop_event = stop_event or threading.Event()
    sniffer_status.update({
        "enabled": True,
        "status": "starting",
        "interfaces": interfaces,
        "error": None,
    })
    try:
        logger.info(f"Starting sniffer on interfaces: {interfaces}")
        sniffer_status.update({"status": "running"})
        while not stop_event.is_set():
            sniff(iface=interfaces, prn=handle_packet, store=False, filter="ip", timeout=1)
    except PermissionError:
        sniffer_status.update({
            "status": "permission_denied",
            "error": "Permission denied. Run with sudo.",
        })
        logger.error("Sniffer failed: Permission denied. Run with sudo.")
    except Exception as e:
        sniffer_status.update({"status": "error", "error": str(e)})
        logger.error(f"Sniffer error: {e}")
    finally:
        if stop_event.is_set():
            sniffer_status.update({"status": "stopped"})
