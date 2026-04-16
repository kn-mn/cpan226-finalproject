import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np

# ------------------------------------------------------------------
# 1. Feature extraction: we collect stats per source IP every window
# ------------------------------------------------------------------
# Data structure: { src_ip: [list_of_features] }
# Features: [packet_count, unique_dst_ports, avg_packet_rate]
ip_stats = defaultdict(lambda: {'packets': 0, 'ports': set(), 'start_time': time.time()})

# Detection window (seconds) – after each window we run ML
WINDOW = 10

def extract_features():
    """Convert collected stats into a numpy array for ML."""
    X = []
    ip_list = []
    current_time = time.time()
    for ip, data in ip_stats.items():
        elapsed = current_time - data['start_time']
        if elapsed == 0:
            elapsed = 0.001
        packet_rate = data['packets'] / elapsed
        # Feature vector: [packet_count, unique_ports, packet_rate]
        features = [data['packets'], len(data['ports']), packet_rate]
        X.append(features)
        ip_list.append(ip)
    return np.array(X), ip_list

def detect_anomalies(features, ip_list):
    """Run Isolation Forest and print anomalies."""
    if len(features) < 2:   # need at least 2 samples for isolation forest
        return
    model = IsolationForest(contamination=0.2, random_state=42)
    predictions = model.fit_predict(features)   # -1 = anomaly, 1 = normal
    for ip, pred in zip(ip_list, predictions):
        if pred == -1:
            # Optional: add rule-based check to reduce false positives
            # For example: high unique ports = port scan
            # We'll simply print the IP as anomalous
            print(f"[!] ANOMALY DETECTED: {ip} (features: {features[ip_list.index(ip)]})")

def packet_callback(packet):
    """Called for every captured packet."""
    if IP in packet:
        src_ip = packet[IP].src
        # Update stats
        ip_stats[src_ip]['packets'] += 1
        if TCP in packet:
            ip_stats[src_ip]['ports'].add(packet[TCP].dport)
        elif UDP in packet:
            ip_stats[src_ip]['ports'].add(packet[UDP].dport)

# ------------------------------------------------------------------
# 2. Main loop: capture packets and run detection every WINDOW seconds
# ------------------------------------------------------------------
def start_detection(interface=None):
    print(f"Starting anomaly detection (window = {WINDOW}s). Press Ctrl+C to stop.")
    last_check = time.time()
    # Start sniffing in a non‑blocking way? We'll use a simple loop with timeout.
    # Sniff with timeout to periodically run ML.
    while True:
        # Capture packets for `WINDOW` seconds, then run detection
        sniff(iface=interface, prn=packet_callback, timeout=WINDOW, store=0)
        # After the window, extract features and detect anomalies
        features, ip_list = extract_features()
        detect_anomalies(features, ip_list)
        # Reset stats for next window
        ip_stats.clear()

if __name__ == "__main__":
    # Optional: specify network interface (e.g., 'eth0', 'Wi-Fi', or None for default)
    start_detection(interface=None)