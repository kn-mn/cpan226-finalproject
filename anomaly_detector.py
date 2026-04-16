from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import time
from collections import defaultdict

# --------------------------------------------------
# 1. Store stats per source IP
# --------------------------------------------------
# ip_stats[src_ip] = {'packets': count, 'ports': set(), 'start_time': timestamp}
ip_stats = defaultdict(
    lambda: {"packets": 0, "ports": set(), "start_time": time.time()}
)

WINDOW = 10  # check for anomalies every 10 seconds


# --------------------------------------------------
# 2. Packet callback: update stats for each packet
# --------------------------------------------------
def packet_callback(packet):
    if IP in packet:  # only IP packets
        src = packet[IP].src  # source IP address
        ip_stats[src]["packets"] += 1
        # record destination port if TCP or UDP
        if TCP in packet:
            ip_stats[src]["ports"].add(packet[TCP].dport)
        elif UDP in packet:
            ip_stats[src]["ports"].add(packet[UDP].dport)


# --------------------------------------------------
# 3. Build feature list from collected stats
# --------------------------------------------------
def get_features():
    X = []  # list of feature vectors
    ip_list = []  # keep IPs in same order
    now = time.time()
    for ip, data in ip_stats.items():
        elapsed = now - data["start_time"]
        if elapsed < 0.001:
            elapsed = 0.001
        rate = data["packets"] / elapsed
        features = [data["packets"], len(data["ports"]), rate]
        X.append(features)
        ip_list.append(ip)
    return X, ip_list


# --------------------------------------------------
# 4. Run ML model and print anomalies
# --------------------------------------------------
def detect_anomalies(features, ip_list):
    if len(features) < 2:
        return  # need at least 2 samples
    model = IsolationForest(contamination=0.2, random_state=42)
    predictions = model.fit_predict(features)  # -1 = anomaly
    for ip, pred, feat in zip(ip_list, predictions, features):
        if pred == -1:
            # filter out weak anomalies (reduce false positives)
            if feat[2] > 20 or feat[1] > 30:
                print(
                    f"[!] ALERT: {ip} | packets={feat[0]}, ports={feat[1]}, rate={feat[2]:.1f}/s"
                )


# --------------------------------------------------
# 5. Main loop
# --------------------------------------------------
def start_detection(interface=None):
    print(f"Monitoring every {WINDOW}s. Press Ctrl+C to stop.")
    while True:
        # capture packets for WINDOW seconds
        sniff(iface=interface, prn=packet_callback, timeout=WINDOW, store=0)
        # now analyse
        features, ip_list = get_features()
        detect_anomalies(features, ip_list)
        # reset for next window
        ip_stats.clear()


if __name__ == "__main__":
    start_detection()
