import netifaces
import statistics


def get_service(port: int) -> str:
    port_map = {
        80: "http", 443: "ssl", 53: "dns", 21: "ftp", 20: "ftp-data",
        22: "ssh", 25: "smtp", 110: "pop3", 143: "imap", 161: "snmp",
        6667: "irc", 1812: "radius", 1813: "radius"
    }
    return port_map.get(port, "-")


def get_active_interfaces() -> list[str]:
    """Auto-detect active network interfaces."""
    interfaces = []
    try:
        for iface in netifaces.interfaces():
            if iface == "lo":
                interfaces.append(iface)
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                interfaces.append(iface)
    except Exception:
        interfaces = ["lo"]
    return interfaces or ["lo"]


def get_local_ips() -> set[str]:
    """
    Return all IPv4 addresses assigned to this machine.
    Used to identify inbound traffic (dst == local IP = traffic TO this machine).
    """
    local_ips = {"127.0.0.1"}
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for addr in addrs.get(netifaces.AF_INET, []):
                ip = addr.get("addr", "")
                if ip:
                    local_ips.add(ip)
    except Exception:
        pass
    return local_ips


def compute_jitter(packets) -> float:
    """Compute jitter (stdev of inter-arrival times in ms)."""
    if len(packets) < 3:
        return 0.0
    intervals = [packets[i][0] - packets[i-1][0] for i in range(1, len(packets))]
    if len(intervals) < 2:
        return 0.0
    return statistics.stdev(intervals) * 1000


def compute_loss(packets) -> int:
    """Estimate packet loss based on TCP retransmissions."""
    if not packets:
        return 0
    loss = 0
    for i in range(1, len(packets)):
        if packets[i][0] - packets[i-1][0] < 0.001 and packets[i][1] == packets[i-1][1]:
            loss += 1
    return loss
