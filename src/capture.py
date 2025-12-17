from scapy.all import rdpcap, Dot11Beacon
import time

def replay_pcap(path):
    pkts = rdpcap(path)
    for pkt in pkts:
        if pkt.haslayer(Dot11Beacon):
            yield {
                "bssid": pkt.addr2,
                "ssid": pkt.info.decode(errors="ignore") if hasattr(pkt, "info") else "",
                "ts": float(pkt.time)
            }
            time.sleep(0.01)
        # else:
        #     print("[DEBUG] Non-beacon packet")
