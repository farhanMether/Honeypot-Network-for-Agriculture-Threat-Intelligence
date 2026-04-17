import socket
from datetime import datetime
import csv
import os

# Create server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8888))
server.listen(5)

print("=== Honeypot Monitoring System Started ===")
print("Listening on port 8888...\n")

ip_count = {}
blocked_ips = set()

# Create CSV file if not exists
if not os.path.exists("log.csv"):
    with open("log.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "IP Address", "Attempts", "Status"])

while True:
    client, addr = server.accept()
    
    ip = addr[0]
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if IP is blocked
    if ip in blocked_ips:
        print(f"🚫 Blocked connection attempt from {ip}")
        client.close()
        continue

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

    # Print log
    print(f"{time} | {ip} | Attempts: {attempts} | Status: {status}")

    # Save to CSV
    with open("log.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([time, ip, attempts, status])

    # Send fake response
    client.send("403 Forbidden - Access Denied".encode())

    client.close()