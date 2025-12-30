from scapy.all import *
import datetime

def extract_ap_features(packet):
    features = {}
    
    if packet.haslayer(Dot11Beacon):
        
        # 1. Signal Strength (RSSI)
        if packet.haslayer(RadioTap):
            if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                features['rssi'] = packet[RadioTap].dBm_AntSignal
            else:
                features['rssi'] = None
        
        # 2. MAC Addresses
        features['bssid'] = packet[Dot11].addr2  # AP's MAC (source)
        features['destination'] = packet[Dot11].addr1
        
        # 3. Sequence Number (for detecting anomalies)
        features['sequence_number'] = packet[Dot11].SC >> 4  # Upper 12 bits
        
        # 4. Beacon Interval
        features['beacon_interval'] = packet[Dot11Beacon].beacon_interval
        
        # 5. Timestamp
        features['timestamp'] = datetime.datetime.now()
        features['ap_timestamp'] = packet[Dot11Beacon].timestamp
        
        # 6. Capabilities (detailed)
        cap = packet[Dot11Beacon].cap
        features['privacy'] = bool(cap & 0x0010)  # Privacy bit (encryption)
        features['ess'] = bool(cap & 0x0001)      # ESS mode
        features['ibss'] = bool(cap & 0x0002)     # IBSS mode
        features['short_preamble'] = bool(cap & 0x0020)
        features['pbcc'] = bool(cap & 0x0040)
        features['channel_agility'] = bool(cap & 0x0080)
        features['short_slot'] = bool(cap & 0x0400)
        features['capability_raw'] = cap  # Store raw value for comparison
        
        # 7. Check if MAC is locally administered
        mac_bytes = packet[Dot11].addr2.split(':')
        first_byte = int(mac_bytes[0], 16)
        features['locally_administered_mac'] = bool(first_byte & 0x02)
        
        # 8. Extract OUI for vendor matching
        features['mac_oui'] = ':'.join(mac_bytes[:3])
        
        # 9. Extract Information Elements
        ie_list = []
        if packet.haslayer(Dot11Elt):
            elt = packet[Dot11Elt]
            
            while isinstance(elt, Dot11Elt):
                ie_list.append(elt.ID)  # Track IE order
                
                # SSID (ID=0)
                if elt.ID == 0:
                    try:
                        features['ssid'] = elt.info.decode('utf-8', errors='ignore')
                    except:
                        features['ssid'] = ''
                
                # Channel (ID=3)
                elif elt.ID == 3:
                    features['channel'] = ord(elt.info)
                
                # Supported Rates (ID=1)
                elif elt.ID == 1:
                    rates = [int(b & 0x7f) * 0.5 for b in elt.info]
                    features['supported_rates'] = rates
                    features['max_rate'] = max(rates) if rates else 0
                
                # Extended Supported Rates (ID=50)
                elif elt.ID == 50:
                    ext_rates = [int(b & 0x7f) * 0.5 for b in elt.info]
                    if 'supported_rates' in features:
                        features['supported_rates'].extend(ext_rates)
                        features['max_rate'] = max(features['supported_rates'])
                
                # RSN/Security (ID=48)
                elif elt.ID == 48:
                    features['encryption_type'] = 'WPA2/WPA3'
                    features['rsn_present'] = True
                
                # WPA (ID=221 with specific OUI)
                elif elt.ID == 221 and len(elt.info) >= 4:
                    # Check for WPA OUI (00:50:f2:01)
                    if elt.info[:4] == b'\x00\x50\xf2\x01':
                        features['encryption_type'] = 'WPA'
                
                # HT Capabilities (ID=45) - 802.11n
                elif elt.ID == 45:
                    features['ht_capable'] = True
                    
                # VHT Capabilities (ID=191) - 802.11ac
                elif elt.ID == 191:
                    features['vht_capable'] = True
                
                # Country Info (ID=7)
                elif elt.ID == 7:
                    try:
                        features['country_code'] = elt.info[:2].decode('utf-8')
                    except:
                        features['country_code'] = None
                
                # Power Constraint (ID=32)
                elif elt.ID == 32:
                    features['power_constraint'] = ord(elt.info)
                
                # Vendor OUI (ID=221)
                elif elt.ID == 221 and len(elt.info) >= 3:
                    oui = ':'.join(f'{b:02x}' for b in elt.info[:3])
                    features['vendor_oui'] = oui
                    features['vendor'] = get_vendor_from_oui(features['mac_oui'])
                
                # Move to next element
                elt = elt.payload
                if not isinstance(elt, Dot11Elt):
                    break
        
        # 10. Information Element metadata
        features['ie_order'] = tuple(ie_list)  # Order of IEs
        features['ie_count'] = len(ie_list)
        
        # Set defaults for missing fields
        features.setdefault('ssid', '')
        features.setdefault('channel', None)
        features.setdefault('encryption_type', 'Open' if not features.get('privacy') else 'Unknown')
        features.setdefault('vendor', get_vendor_from_oui(features.get('mac_oui', '')))
        features.setdefault('supported_rates', [])
        features.setdefault('max_rate', 0)
        features.setdefault('ht_capable', False)
        features.setdefault('vht_capable', False)
        features.setdefault('rsn_present', False)
        features.setdefault('country_code', None)
        features.setdefault('power_constraint', None)
    
    return features

def get_vendor_from_oui(oui):
    oui_db = {
        '00:11:22': 'Cisco',
        '00:1a:2b': 'D-Link',
        '00:1c:2d': 'TP-Link',
        '00:1e:2f': 'Netgear',
        '00:20:21': 'Linksys',
        '00:22:23': 'Belkin',

    }
    return oui_db.get(oui, 'Unknown')

# Usage example
def packet_handler(packet):
    if packet.haslayer(Dot11Beacon):
        features = extract_ap_features(packet)
        print(f"SSID: {features['ssid']}")
        print(f"BSSID: {features['bssid']}")
        print(f"Channel: {features['channel']}")
        print(f"RSSI: {features['rssi']} dBm")
        print(f"Encryption: {features['encryption_type']}")
        print(f"Vendor: {features['vendor']}")
        print(f"Beacon Interval: {features['beacon_interval']} ms")
        print(f"Timestamp: {features['timestamp']}")
        print(f"Privacy: {features['privacy']}")
        print("-" * 50)

# Capture packets
sniff(iface='mon1', prn=packet_handler, count=10)