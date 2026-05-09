from scapy.all import sniff, IP, TCP, UDP
from app.state import flow_table, flow_lock, connection_log
from app.core.flow import FlowRecord
from app.utils.network import get_service, get_active_interfaces
from app.config import logger

def get_tcp_flags_str(pkt):
    return str(pkt[TCP].flags) if TCP in pkt else ""

def handle_packet(pkt):
    if IP not in pkt: return

    src_ip, dst_ip, proto, ttl = pkt[IP].src, pkt[IP].dst, pkt[IP].proto, pkt[IP].ttl
    pkt_size, pkt_time = len(pkt), time.time()
    sport = pkt.sport if hasattr(pkt, 'sport') else 0
    dport = pkt.dport if hasattr(pkt, 'dport') else 0
    flags = get_tcp_flags_str(pkt)
    tcp_seq = pkt[TCP].seq if TCP in pkt else 0
    tcp_win = pkt[TCP].window if TCP in pkt else 0

    fwd_key, rev_key = (src_ip, sport, dst_ip, dport), (dst_ip, dport, src_ip, sport)

    with flow_lock:
        if fwd_key in flow_table:
            flow_table[fwd_key].add_src_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow_table[fwd_key].update_state(flags)
        elif rev_key in flow_table:
            flow_table[rev_key].add_dst_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow_table[rev_key].update_state(flags)
        else:
            flow = FlowRecord(src_ip, dst_ip, sport, dport, proto)
            flow.add_src_packet(pkt_time, pkt_size, ttl, flags, tcp_seq, tcp_win)
            flow.update_state(flags)
            flow_table[fwd_key] = flow
            connection_log.append({
                "time": pkt_time, "src_ip": src_ip, "dst_ip": dst_ip,
                "sport": sport, "dport": dport, "service": get_service(dport)
            })

import time # Needed for pkt_time

def run_sniffer():
    try:
        interfaces = get_active_interfaces()
        logger.info(f"Starting sniffer on interfaces: {interfaces}")
        sniff(iface=interfaces, prn=handle_packet, store=False, filter="ip")
    except PermissionError:
        logger.error("❌ Sniffer failed: Permission denied. Run with sudo.")
    except Exception as e:
        logger.error(f"❌ Sniffer error: {e}")
