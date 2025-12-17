import sys
from collections import defaultdict
from capture import replay_pcap
from features import compute_features
from baseline import CUSUM, Baseline
import json

BASELINE_FILE = "../data/baseline.json"

if len(sys.argv) != 3:
    print("Usage: python3 main.py <learn|detect> <pcap>")
    sys.exit(1)

MODE = sys.argv[1]
PCAP = sys.argv[2]

buffers = defaultdict(list)
cusums = defaultdict(CUSUM)
baselines = defaultdict(Baseline)

saved_baselines = {}
if MODE == "detect":
    import json
    saved_baselines = json.load(open(BASELINE_FILE))

for pkt in replay_pcap(PCAP):
    bssid = pkt["bssid"]
    buffers[bssid].append(pkt["ts"])

    # keep last 10 seconds
    buffers[bssid] = [t for t in buffers[bssid] if pkt["ts"] - t <= 10]

    feats = compute_features(buffers[bssid])
    if not feats:
        continue

    # LEARNING MODE
    if MODE == "learn":
        base = baselines[bssid]
        base.update(feats)
        print(f"[LEARNING] {pkt['ssid']} {bssid}")

    # DETECTION MODE
    elif MODE == "detect":
        if bssid not in saved_baselines:
            continue 

        delta = abs(feats["mean_interval"] - saved_baselines[bssid]["mean_interval"]) / saved_baselines[bssid]["mean_interval"]
        if cusums[bssid].update(delta):
            if delta>0.18:
                print(f"[ALERT] {pkt['ssid']} sustained drift detected (delta={delta:.3f})")


if MODE == "learn":
    out = {}
    for bssid, base in baselines.items():
        if base.ready():
            mean, jitter = base.stats()
            out[bssid] = {
                "mean_interval": mean,
                "jitter": jitter
            }

    json.dump(out, open(BASELINE_FILE, "w"), indent=2)
    print(f"[+] Baseline saved to {BASELINE_FILE}")

"""
sudo iw phy phy1 interface add mon1 type monitor
sudo ip link set mon1 up
"""