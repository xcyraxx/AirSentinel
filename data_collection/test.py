from scapy.all import sniff
from capture import extract_ap_features
from extract import FeatureExtractor
from channel_hopper import ChannelHopper

interface = "mon1"
hopper = ChannelHopper(interface, channels=[1,6,11], dwell_time=1.0)  # hopping only between non-overlapping channels in 2.4ghz
hopper.start()														  # hopping on 5GHz channels not done atm , can implement later.

extractor = FeatureExtractor(use_packet_time=False)

def packet_handler(packet):
	features = extract_ap_features(packet)
	if features:
		features['channel'] = hopper.get_current_channel()
		extractor.observe_packet(features)
		
sniff(iface=interface, prn=packet_handler, count=10)
hopper.stop()
