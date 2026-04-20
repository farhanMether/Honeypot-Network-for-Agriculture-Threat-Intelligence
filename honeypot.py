<<<<<<< HEAD
import socket
from datetime import datetime
import csv
import threading
import os

BLOCKED_IPS_FILE = "blocked_ips.txt"
lock = threading.Lock()

# Create server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8888))
server.listen(5)

print("=" * 55)
print("   AgriSense Honeypot - Agriculture Threat Monitor")
print("=" * 55)
print(f"  Project  : Honeypot Network for Agriculture Threat Intel")
print(f"  Port     : 8888")
print(f"  Protocol : TCP (Socket)")
print(f"  Logging  : log.csv")
print(f"  Blocking : blocked_ips.txt")
print(f"  Status   : ACTIVE")
print("=" * 55)
print("  Waiting for connections...\n")

ip_count = {}
blocked_ips = set()

# Load blocked IPs from file if it exists
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips = set(line.strip() for line in f if line.strip())
    print(f"[!] Loaded {len(blocked_ips)} previously blocked IPs\n")

# Create CSV file if not exists
if not os.path.exists("log.csv"):
    with open("log.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "IP Address", "Port", "Attempts", "Status"])

def handle_client(client, addr):
    ip = addr[0]
    port = addr[1]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with lock:
        # Check if IP is blocked
        if ip in blocked_ips:
            print(f"🚫 Blocked connection attempt from {ip}")
            client.close()
            return

        # Count attempts
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1

        attempts = ip_count[ip]
        status = "Normal"

        # Detect suspicious activity
        if attempts >= 5:
            status = "Suspicious"
            blocked_ips.add(ip)
            print(f"⚠ ALERT: Suspicious IP detected and blocked → {ip}")
            with open(BLOCKED_IPS_FILE, "a") as f:
                f.write(ip + "\n")

        # Print log
        print(f"{timestamp} | {ip}:{port} | Attempts: {attempts} | Status: {status}")

        # Save to CSV
        with open("log.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, ip, port, attempts, status])

    # Send fake response (outside lock)
    client.send("AgriSense IoT Gateway v2.1 - 403 Access Denied".encode())
    client.close()
try:
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.start()
except KeyboardInterrupt:
    print("\n[!] Honeypot shutting down gracefully...")
    server.close()
=======
import socket
from datetime import datetime
import csv
import threading
import os

BLOCKED_IPS_FILE = "blocked_ips.txt"
lock = threading.Lock()

# Create server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8888))
server.listen(5)

print("=" * 55)
print("   AgriSense Honeypot - Agriculture Threat Monitor")
print("=" * 55)
print(f"  Project  : Honeypot Network for Agriculture Threat Intel")
print(f"  Port     : 8888")
print(f"  Protocol : TCP (Socket)")
print(f"  Logging  : log.csv")
print(f"  Blocking : blocked_ips.txt")
print(f"  Status   : ACTIVE")
print("=" * 55)
print("  Waiting for connections...\n")

ip_count = {}
blocked_ips = set()

# Load blocked IPs from file if it exists
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips = set(line.strip() for line in f if line.strip())
    print(f"[!] Loaded {len(blocked_ips)} previously blocked IPs\n")

# Create CSV file if not exists
if not os.path.exists("log.csv"):
    with open("log.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "IP Address", "Port", "Attempts", "Status"])

def handle_client(client, addr):
    ip = addr[0]
    port = addr[1]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with lock:
        # Check if IP is blocked
        if ip in blocked_ips:
            print(f"🚫 Blocked connection attempt from {ip}")
            client.close()
            return

        # Count attempts
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1

        attempts = ip_count[ip]
        status = "Normal"

        # Detect suspicious activity
        if attempts >= 5:
            status = "Suspicious"
            blocked_ips.add(ip)
            print(f"⚠ ALERT: Suspicious IP detected and blocked → {ip}")
            with open(BLOCKED_IPS_FILE, "a") as f:
                f.write(ip + "\n")

        # Print log
        print(f"{timestamp} | {ip}:{port} | Attempts: {attempts} | Status: {status}")

        # Save to CSV
        with open("log.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, ip, port, attempts, status])

    # Send fake response (outside lock)
    client.send("AgriSense IoT Gateway v2.1 - 403 Access Denied".encode())
    client.close()
try:
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.start()
except KeyboardInterrupt:
    print("\n[!] Honeypot shutting down gracefully...")
    server.close()
>>>>>>> 42433d9cad2745e0756b6ebaca530ba0473cb07a
    print("[✓] Server closed. Goodbye.")