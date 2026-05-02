from flask import Flask, render_template, jsonify, request
import socket
import threading
import csv
import os
import json
from datetime import datetime

app = Flask(__name__)

# ── Config ──────────────────────────────────────────────────────────────────
LOG_FILE         = "log.csv"
BLOCKED_IPS_FILE = "blocked_ips.txt"
HONEYPOT_PORT    = 8888

# ── Shared State ─────────────────────────────────────────────────────────────
lock         = threading.Lock()
ip_count     = {}
blocked_ips  = set()
honeypot_running = False
server_socket    = None
alerts           = []   # recent alert messages

# ── Bootstrap files ──────────────────────────────────────────────────────────
def bootstrap():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["Time","IP Address","Port","Attempts","Status"])
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    blocked_ips.add(ip)

bootstrap()

# ── Honeypot Core ─────────────────────────────────────────────────────────────
def handle_client(client, addr):
    ip   = addr[0]
    port = addr[1]
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with lock:
        if ip in blocked_ips:
            try:
                client.send(b"AgriSense IoT Gateway v2.1 - 403 Access Denied [BLOCKED]")
            except:
                pass
            client.close()
            return

        ip_count[ip] = ip_count.get(ip, 0) + 1
        attempts = ip_count[ip]
        status   = "Normal"

        if attempts >= 5:
            status = "Suspicious"
            if ip not in blocked_ips:
                blocked_ips.add(ip)
                with open(BLOCKED_IPS_FILE, "a") as f:
                    f.write(ip + "\n")
                alerts.append({
                    "time": ts,
                    "message": f"ALERT — Suspicious IP blocked: {ip} after {attempts} attempts"
                })
                if len(alerts) > 50:
                    alerts.pop(0)

        with open(LOG_FILE, "a", newline="") as f:
            csv.writer(f).writerow([ts, ip, port, attempts, status])

    try:
        client.send(b"AgriSense IoT Gateway v2.1 - 403 Access Denied")
    except:
        pass
    client.close()


def honeypot_thread():
    global server_socket, honeypot_running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(("0.0.0.0", HONEYPOT_PORT))
        server_socket.listen(10)
        server_socket.settimeout(1.0)
        while honeypot_running:
            try:
                client, addr = server_socket.accept()
                t = threading.Thread(target=handle_client, args=(client, addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
            except:
                break
    except Exception as e:
        print(f"Honeypot error: {e}")
    finally:
        try:
            server_socket.close()
        except:
            pass
        honeypot_running = False


# ── Flask Routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({"running": honeypot_running, "port": HONEYPOT_PORT})


@app.route("/api/start", methods=["POST"])
def api_start():
    global honeypot_running
    if not honeypot_running:
        honeypot_running = True
        t = threading.Thread(target=honeypot_thread)
        t.daemon = True
        t.start()
        alerts.append({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Honeypot STARTED on port {HONEYPOT_PORT}"})
    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global honeypot_running
    honeypot_running = False
    alerts.append({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "message": "Honeypot STOPPED by operator"})
    return jsonify({"ok": True})


@app.route("/api/logs")
def api_logs():
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    rows.reverse()          # newest first
    return jsonify(rows[:200])


@app.route("/api/stats")
def api_stats():
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

    total      = len(rows)
    suspicious = sum(1 for r in rows if r.get("Status") == "Suspicious")
    normal     = total - suspicious
    blocked    = len(blocked_ips)

    # attempts per IP
    ip_map = {}
    for r in rows:
        ip = r.get("IP Address","")
        ip_map[ip] = ip_map.get(ip, 0) + 1

    # attempts over time (group by hour)
    time_map = {}
    for r in rows:
        t = r.get("Time","")
        hour = t[:13] if len(t) >= 13 else t
        time_map[hour] = time_map.get(hour, 0) + 1

    return jsonify({
        "total": total,
        "suspicious": suspicious,
        "normal": normal,
        "blocked": blocked,
        "ip_chart": {"labels": list(ip_map.keys())[-10:],
                     "values": list(ip_map.values())[-10:]},
        "time_chart": {"labels": list(time_map.keys()),
                       "values": list(time_map.values())},
    })


@app.route("/api/blocked")
def api_blocked():
    return jsonify(sorted(list(blocked_ips)))


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = request.json.get("ip","").strip()
    with lock:
        blocked_ips.discard(ip)
        ip_count.pop(ip, None)
        # rewrite file
        with open(BLOCKED_IPS_FILE, "w") as f:
            for b in blocked_ips:
                f.write(b + "\n")
    alerts.append({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "message": f"IP unblocked by operator: {ip}"})
    return jsonify({"ok": True})


@app.route("/api/clear_logs", methods=["POST"])
def api_clear_logs():
    with lock:
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["Time","IP Address","Port","Attempts","Status"])
        ip_count.clear()
    return jsonify({"ok": True})


@app.route("/api/alerts")
def api_alerts():
    return jsonify(list(reversed(alerts[-20:])))


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  AgriSense Honeypot — Web Dashboard")
    print("="*55)
    print("  Open browser at: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, port=5000, threaded=True)
