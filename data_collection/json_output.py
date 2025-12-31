import json
import numpy as np
from datetime import datetime


def create_output_data(bssids, feature_vectors, bssid_info, capture_duration=None):
    """
    Create JSON output data structure from extracted features.
    
    Args:
        bssids: List of BSSID strings
        feature_vectors: List of feature dictionaries corresponding to BSSIDs
        bssid_info: Dictionary mapping BSSID to info (ssid, vendor, etc.)
        capture_duration: Optional capture duration in seconds (for PCAP mode)
    
    Returns:
        Dictionary containing structured output data
    """
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'total_aps': len(bssids),
        'access_points': []
    }
    
    if capture_duration is not None:
        output_data['capture_duration'] = capture_duration
    
    for i, bssid in enumerate(bssids):
        ap_data = {
            'bssid': bssid,
            'ssid': bssid_info[bssid]['ssid'],
            'vendor': bssid_info[bssid]['vendor'],
            'features': {}
        }
        
        # Convert numpy types to JSON-serializable types
        for key, value in feature_vectors[i].items():
            if isinstance(value, (np.integer, np.floating)):
                ap_data['features'][key] = float(value)
            elif isinstance(value, np.ndarray):
                ap_data['features'][key] = value.tolist()
            else:
                ap_data['features'][key] = value
        
        output_data['access_points'].append(ap_data)
    
    return output_data


def save_to_json(output_data, output_dir, mode='pcap'):
    """
    Save output data to JSON file.
    
    Args:
        output_data: Dictionary containing the data to save
        output_dir: Directory to save the file in
        mode: 'pcap' or 'live' to determine filename prefix
    
    Returns:
        Path to the saved file
    """
    json_filename = f"features_{mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = f"{output_dir}/{json_filename}"
    
    with open(filepath, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    return filepath


def print_save_summary(output_data, filepath):
    """
    Print summary of saved data.
    
    Args:
        output_data: The data that was saved
        filepath: Path where data was saved
    """
    num_aps = output_data['total_aps']
    print(f"[+] Extracted features for {num_aps} access points")
    print(f"[+] Saved to: {filepath}")

