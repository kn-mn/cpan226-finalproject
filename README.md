# Anomaly Detector

A simple network anomaly detection tool that captures IP packets, extracts source IP packet statistics, and uses `scikit-learn`'s `IsolationForest` to flag suspicious source IP behavior.

## Requirements

- Python 3.8+ (Python 3.11 or newer recommended)
- `scapy`
- `scikit-learn`
- Administrator/root privileges to capture network packets

## Setup

1. Open a terminal in the repository root:

   ```bash
   cd finalproject
   ```

2. Create a virtual environment (if not already present):

   ```bash
   python3 -m venv .venv
   ```

3. Activate the virtual environment:

   ```bash
   source .venv/bin/activate
   ```

4. Install dependencies:

   ```bash
   pip install --upgrade pip
   pip install scapy scikit-learn
   ```

## Usage

Run the anomaly detector from the repository root:

```bash
sudo python anomaly_detector.py
```

> `sudo` is usually required on macOS and Linux to capture packets with `scapy`.

## Notes

- The script monitors packets in 10-second windows.
- It treats source IP addresses as anomalous when packet rate or ports accessed exceed the default thresholds.
- You can add `iface=<network_interface>` in `start_detection()` or modify the script to specify a live interface.

## Troubleshooting

- If `scapy` installation fails, make sure `libpcap` is installed on your system.
- If packet capture returns no data, verify the correct network interface and proper permissions.
