#!/usr/bin/env python3
import os
import time
from datetime import datetime
import nmap

# --- Configuration ---
NETWORK = "192.168.236.0/24"  # CHANGE THIS to your subnet (use `ip a` to find it)
SCAN_INTERVAL = 60          # Time in seconds between scans
LOG_DIR = "scan_logs"
MAX_LOG_FILES = 100

def setup():
    os.makedirs(LOG_DIR, exist_ok=True)

def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts=NETWORK, arguments='-sn')
    devices = {}

    for host in nm.all_hosts():
        ip = host
        mac = nm[host]['addresses'].get('mac', 'Unknown')
        devices[ip] = mac

    return devices

def save_scan(devices):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{LOG_DIR}/scan_{timestamp}.txt"
    with open(filename, "w") as f:
        for ip, mac in devices.items():
            f.write(f"{ip} - {mac}\n")
    cleanup_logs()
    return filename

def cleanup_logs():
    files = sorted([
        f for f in os.listdir(LOG_DIR)
        if f.startswith("scan_") and f.endswith(".txt")
    ])
    while len(files) > MAX_LOG_FILES:
        oldest = files.pop(0)
        os.remove(os.path.join(LOG_DIR, oldest))
        print(f"[+] Deleted old log: {oldest}")

def monitor():
    print(f"[*] Monitoring network {NETWORK}... (Press Ctrl+C to stop)")
    previous_devices = scan_network()
    save_scan(previous_devices)

    while True:
        current_devices = scan_network()

        added = {ip: mac for ip, mac in current_devices.items() if ip not in previous_devices}
        removed = {ip: mac for ip, mac in previous_devices.items() if ip not in current_devices}

        if added or removed:
            print(f"\n[!] ALERT: Network change detected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            if added:
                print("  [+] New Devices:")
                for ip, mac in added.items():
                    print(f"    IP: {ip} | MAC: {mac}")
            if removed:
                print("  [-] Removed Devices:")
                for ip, mac in removed.items():
                    print(f"    IP: {ip} | MAC: {mac}")

            save_scan(current_devices)
            previous_devices = current_devices

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    setup()
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
