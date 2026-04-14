import time

ip_activity = {}
baseline = {}

trusted_ips = ["2a03:2880"]  # Facebook example


def analyze_traffic(src, dst, port=None):

    # Trusted traffic skip
    if any(src.startswith(t) for t in trusted_ips):
        return "LOW RISK", ["Trusted traffic"]

    score = 0
    reasons = []

    now = time.time()

    if src not in ip_activity:
        ip_activity[src] = []

    ip_activity[src].append(now)

    ip_activity[src] = [t for t in ip_activity[src] if now - t < 10]

    rate = len(ip_activity[src])

    if src not in baseline:
        baseline[src] = rate

    if rate > baseline[src] * 2:
        score += 3
        reasons.append("Behavior anomaly")

    if port in [4444, 5555, 6666, 9999]:
        score += 3
        reasons.append("Suspicious port")

    if src == dst:
        score += 2
        reasons.append("Loopback anomaly")

    if score >= 5:
        return "HIGH RISK", reasons
    elif score >= 3:
        return "MEDIUM RISK", reasons
    else:
        return "LOW RISK", reasons