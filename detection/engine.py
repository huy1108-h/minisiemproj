from datetime import datetime, timedelta


class RealtimeDetectionEngine:
    def __init__(self, brute_force_threshold=5, spraying_threshold=5, dos_threshold=10):
        self.brute_force_threshold = brute_force_threshold
        self.spraying_threshold = spraying_threshold
        self.dos_threshold = dos_threshold
        
        self.failed_logins = {}      # (user, ip): [timestamps]
        self.failed_users = {}       # ip: set(users)
        self.requests_by_ip = {}     # ip: [timestamps]
        
        self.sensitive_actions = {
            "privilege_escalation": "CRITICAL",
            "delete_logs": "CRITICAL",
            "access_shadow": "HIGH",
            "disable_firewall": "CRITICAL",
            "sql_injection_attempt": "HIGH"
        }

    def process_event(self, event):
        alerts = []
        action = event.get("action")
        ip = event.get("ip")
        user = event.get("user")
        raw_timestamp = event.get("timestamp")

        try:
            event_time = datetime.strptime(raw_timestamp, "%Y-%m-%d %H:%M:%S")
        except Exception:
            event_time = datetime.now()

        # 1. Rule: Suspicious / Sensitive Actions
        if action in self.sensitive_actions:
            alerts.append({
                "rule": "SUSPICIOUS_SENSITIVE_ACTION",
                "severity": self.sensitive_actions[action],
                "user": user,
                "ip": ip,
                "timestamp": raw_timestamp,
                "message": f"Suspicious action '{action}' triggered by '{user or 'unknown'}' from IP '{ip or 'unknown'}'"
            })

        # 2. Rule: High Request Rate / DoS Detection (10 requests in 60s)
        if ip:
            if ip not in self.requests_by_ip:
                self.requests_by_ip[ip] = []
            self.requests_by_ip[ip].append(event_time)
            window_dos = event_time - timedelta(seconds=60)
            self.requests_by_ip[ip] = [t for t in self.requests_by_ip[ip] if t >= window_dos]
            if len(self.requests_by_ip[ip]) == self.dos_threshold:
                alerts.append({
                    "rule": "HIGH_REQUEST_RATE_DOS",
                    "severity": "CRITICAL" if self.dos_threshold >= 20 else "HIGH",
                    "ip": ip,
                    "user": user,
                    "timestamp": raw_timestamp,
                    "message": f"Possible DoS activity: {self.dos_threshold} requests from IP {ip} within 60s"
                })

        # 3. Rules on login_failed
        if action == "login_failed":
            # 3a. Brute Force Login
            key = (user, ip)
            if key not in self.failed_logins:
                self.failed_logins[key] = []
            self.failed_logins[key].append(event_time)
            window_bf = event_time - timedelta(minutes=5)
            self.failed_logins[key] = [t for t in self.failed_logins[key] if t >= window_bf]
            if len(self.failed_logins[key]) == self.brute_force_threshold:
                alerts.append({
                    "rule": "BRUTE_FORCE_LOGIN",
                    "severity": "HIGH",
                    "user": user,
                    "ip": ip,
                    "timestamp": raw_timestamp,
                    "message": f"Detected {self.brute_force_threshold} failed login attempts within 5 minutes"
                })

            # 3b. Password Spraying
            if ip:
                if ip not in self.failed_users:
                    self.failed_users[ip] = set()
                if user:
                    self.failed_users[ip].add(user)
                if len(self.failed_users[ip]) == self.spraying_threshold:
                    alerts.append({
                        "rule": "PASSWORD_SPRAYING",
                        "severity": "HIGH",
                        "ip": ip,
                        "timestamp": raw_timestamp,
                        "message": f"Detected failed login attempts for {self.spraying_threshold} different users from IP {ip}"
                    })

        return alerts


def run_detection(events):
    engine = RealtimeDetectionEngine()
    alerts = []
    for event in events:
        alerts.extend(engine.process_event(event))
    return alerts