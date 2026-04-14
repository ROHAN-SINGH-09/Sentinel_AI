import psutil
from scapy.all import sniff
import time

from ai_engine.ai_model import analyze_traffic
from backend.logger import log_event
from backend.response import alert_user
from backend.agent import take_action

LOCAL_IP_PREFIXES = ("192.", "10.", "172.", "2409")

DOS_THRESHOLD = 40
PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = 10

ip_count = {}
port_access = {}
last_reset_time = time.time()
alerted_ips = set()


def detect_dos(ip):
    if ip.startswith(LOCAL_IP_PREFIXES):
        return None

    ip_count[ip] = ip_count.get(ip, 0) + 1

    if ip_count[ip] > DOS_THRESHOLD:
        return f"🚨 DoS Attack from {ip}"

    return None


def detect_port_scan(ip, port):
    if ip.startswith(LOCAL_IP_PREFIXES):
        return None

    if ip not in port_access:
        port_access[ip] = set()

    port_access[ip].add(port)

    if len(port_access[ip]) > PORT_SCAN_THRESHOLD:
        return f"⚠️ Port Scan from {ip}"

    return None


def get_process_name():
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid:
                return psutil.Process(conn.pid).name()
    except:
        pass
    return "System Process"


def capture_packets():
    global last_reset_time

    print("\n=== SentinelAI Running (Continuous Mode) ===\n")
    print("Waiting for traffic... (Open browser or run ping)\n")

    def packet_callback(packet):
        global last_reset_time

        try:
            now = time.time()

            # Reset counters every time window
            if now - last_reset_time > TIME_WINDOW:
                ip_count.clear()
                port_access.clear()
                last_reset_time = now

            src = dst = port = None

            # IPv4
            if packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst
                print(f"[IPv4] {src} → {dst}")

            # IPv6 (ignore local noise)
            elif packet.haslayer("IPv6"):
                src = packet["IPv6"].src
                dst = packet["IPv6"].dst

                if src.startswith("fe80"):
                    return

                print(f"[IPv6] {src} → {dst}")

            # TCP port
            if packet.haslayer("TCP"):
                port = packet["TCP"].dport

            # ===== DoS Detection =====
            if src:
                alert = detect_dos(src)

                if alert and src not in alerted_ips:
                    alerted_ips.add(src)
                    alert_user(alert)
                    log_event(alert)

            # ===== Port Scan Detection =====
            if src and port:
                alert = detect_port_scan(src, port)

                if alert and src not in alerted_ips:
                    alerted_ips.add(src)
                    alert_user(alert)
                    log_event(alert)

            # ===== AI + AGENT =====
            if src and dst:
                process_name = get_process_name()

                risk, reasons = analyze_traffic(src, dst, port)

                print(f"[AI] {risk} → {reasons} | {process_name}")

                log_event(f"{src} → {dst} | {risk} | {reasons} | {process_name}")

                actions = take_action(src, risk, process_name)

                for action in actions:
                    print(f"[AGENT]: {action}")
                    log_event(action)

        except Exception as e:
            print("[ERROR]", e)

    # 🔥 FIXED: Continuous sniffing
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    capture_packets()