import time

class FlowRecord:
    """Tracks a single network flow (src:sport -> dst:dport)."""
    def __init__(self, src_ip, dst_ip, sport, dport, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.proto = proto

        self.start_time = time.time()
        self.last_time = self.start_time

        self.src_packets = []   
        self.src_ttls = []
        self.src_flags = []
        self.src_tcp_seq = []
        self.src_tcp_win = []

        self.dst_packets = []   
        self.dst_ttls = []
        self.dst_flags = []
        self.dst_tcp_seq = []
        self.dst_tcp_win = []

        self.syn_time = None
        self.synack_time = None
        self.ack_time = None

        self.state = "REQ"
        self.is_finished = False

    def add_src_packet(self, pkt_time, size, ttl, flags="", tcp_seq=0, tcp_win=0):
        self.src_packets.append((pkt_time, size))
        self.src_ttls.append(ttl)
        self.src_flags.append(flags)
        if tcp_seq: self.src_tcp_seq.append(tcp_seq)
        if tcp_win: self.src_tcp_win.append(tcp_win)
        self.last_time = pkt_time

        if "S" in flags and "A" not in flags and self.syn_time is None:
            self.syn_time = pkt_time
        if "A" in flags and "S" not in flags and self.synack_time and not self.ack_time:
            self.ack_time = pkt_time

    def add_dst_packet(self, pkt_time, size, ttl, flags="", tcp_seq=0, tcp_win=0):
        self.dst_packets.append((pkt_time, size))
        self.dst_ttls.append(ttl)
        self.dst_flags.append(flags)
        if tcp_seq: self.dst_tcp_seq.append(tcp_seq)
        if tcp_win: self.dst_tcp_win.append(tcp_win)
        self.last_time = pkt_time

        if "S" in flags and "A" in flags and self.synack_time is None:
            self.synack_time = pkt_time

    def update_state(self, flags):
        if "S" in flags and "A" not in flags:
            self.state = "REQ"
        elif "S" in flags and "A" in flags:
            self.state = "CON"
        elif "F" in flags:
            self.state = "FIN"
            self.is_finished = True
        elif "R" in flags:
            self.state = "RST"
            self.is_finished = True
        elif "A" in flags:
            if self.state == "REQ":
                self.state = "CON"
