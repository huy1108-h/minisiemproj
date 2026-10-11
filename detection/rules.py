from datetime import datetime, timedelta


def detect_brute_force(events, threshold=5, window_minutes=5):
    failed_logins = {}
    alerts = []

    for event in events:
        if event.get("action") != "login_failed":
            continue

        user = event.get("user")
        ip = event.get("ip")

        timestamp = datetime.strptime(
            event.get("timestamp"),
            "%Y-%m-%d %H:%M:%S"
        )

        key = (user, ip)

        if key not in failed_logins:
            failed_logins[key] = []

        failed_logins[key].append(timestamp)

        window_start = timestamp - timedelta(minutes=window_minutes)

        failed_logins[key] = [
            time
            for time in failed_logins[key]
            if time >= window_start
        ]

        if len(failed_logins[key]) == threshold:
            alerts.append({
                "rule": "BRUTE_FORCE_LOGIN",
                "severity": "HIGH",
                "user": user,
                "ip": ip,
                "failed_attempts": threshold,
                "window_minutes": window_minutes,
                "timestamp": event.get("timestamp"),
                "message": (
                    f"Detected {threshold} failed login attempts "
                    f"within {window_minutes} minutes"
                )
            })

    return alerts

def detect_password_spraying(events, threshold = 5):
    failed_users = {}
    alerts = []

    for event in events:
        if event.get("action") != "login_failed":
            continue
        ip = event.get("ip")
        user = event.get("user")
        if ip not in failed_users:
            failed_users[ip] = set()


        failed_users[ip].add(user)

        if len(failed_users[ip]) == threshold:
            alerts.append({
                "rule": "PASSWORD_SPRAYING",
                "severity": "HIGH",
                "ip": ip,
                "message": f"Detected failed login attempts for {threshold} different users from the same IP",
            })
    return alerts


def detect_high_request_rate(events, threshold=10, window_seconds=60):
    requests_by_ip = {}
    alerts = []

    for event in events:
        ip = event.get("ip")
        if not ip:
            continue

        try:
            timestamp = datetime.strptime(
                event.get("timestamp"),
                "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            continue

        if ip not in requests_by_ip:
            requests_by_ip[ip] = []

        requests_by_ip[ip].append(timestamp)

        window_start = timestamp - timedelta(seconds=window_seconds)
        requests_by_ip[ip] = [
            t for t in requests_by_ip[ip] if t >= window_start
        ]

        if len(requests_by_ip[ip]) == threshold:
            alerts.append({
                "rule": "HIGH_REQUEST_RATE_DOS",
                "severity": "CRITICAL" if threshold >= 20 else "HIGH",
                "ip": ip,
                "user": event.get("user"),
                "timestamp": event.get("timestamp"),
                "message": (
                    f"Possible DoS/Brute activity: {threshold} requests from IP {ip} "
                    f"within {window_seconds} seconds"
                )
            })

    return alerts


def detect_suspicious_actions(events):
    sensitive_actions = {
        "privilege_escalation": "CRITICAL",
        "delete_logs": "CRITICAL",
        "access_shadow": "HIGH",
        "disable_firewall": "CRITICAL",
        "sql_injection_attempt": "HIGH"
    }

    alerts = []
    for event in events:
        action = event.get("action")
        if action in sensitive_actions:
            alerts.append({
                "rule": "SUSPICIOUS_SENSITIVE_ACTION",
                "severity": sensitive_actions[action],
                "user": event.get("user"),
                "ip": event.get("ip"),
                "timestamp": event.get("timestamp"),
                "message": (
                    f"Sensitive/Malicious action '{action}' executed "
                    f"by user '{event.get('user') or 'unknown'}' from IP '{event.get('ip') or 'unknown'}'"
                )
            })

    return alerts

