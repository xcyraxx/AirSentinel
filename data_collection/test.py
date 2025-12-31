from scapy.all import sniff
from capture import extract_ap_features
from extract import FeatureExtractor
from channel_hopper import ChannelHopper
from json_output import create_output_data, save_to_json, print_save_summary

interface = "wlan0mon"
hopper = ChannelHopper(interface, channels=[1,6,11], dwell_time=1.0)  # hopping only between non-overlapping channels in 2.4ghz
hopper.start()														  # hopping on 5GHz channels not done atm , can implement later.

extractor = FeatureExtractor(use_packet_time=False)

def packet_handler(packet):
	features = extract_ap_features(packet)
	if features:
		features['channel'] = hopper.get_current_channel()
		extractor.observe_packet(features)
		
print(f"[*] Starting packet capture on {interface}...")
sniff(iface=interface, prn=packet_handler, count=200)
hopper.stop()
print("[+] Capture completed")

feature_vectors = []
bssids = []

for bssid in extractor.ap_observations.keys():
	features = extractor.extract_features(bssid, window_seconds=300)
	if features:
		feature_vectors.append(features)
		bssids.append(bssid)

if bssids:
	output_data = create_output_data(
		bssids=bssids,
		feature_vectors=feature_vectors,
		bssid_info=extractor.bssid_info
	)
	
	filepath = save_to_json(output_data, output_dir="../data", mode='test')
	print_save_summary(output_data, filepath)
else:
	print("[!] No APs detected")
