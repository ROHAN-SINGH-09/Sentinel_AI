blocked_ips = set()

def take_action(ip, risk, process):
    actions = []

    if risk == "HIGH RISK":
        if ip not in blocked_ips:
            blocked_ips.add(ip)
            actions.append(f"Blocked IP: {ip}")

        if process not in ["chrome.exe", "explorer.exe"]:
            actions.append(f"Suspicious process: {process}")

    elif risk == "MEDIUM RISK":
        actions.append(f"Monitoring {ip}")

    return actions