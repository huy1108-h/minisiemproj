import time
import random
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("collector/sample.log")


def append_log(line: str):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[GENERATED LOG] {line}")


def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def simulate_normal_traffic():
    users = ["alice", "bob", "charlie", "david", "elena"]
    user = random.choice(users)
    ip = f"192.168.1.{random.randint(10, 50)}"
    log = f"{get_current_time()} INFO user={user} action=login ip={ip}"
    append_log(log)


def simulate_brute_force():
    target_ip = "192.168.1.188"
    print("\n[!] Simulating Brute Force Attack on 'admin'...")
    for i in range(5):
        log = f"{get_current_time()} WARNING user=admin action=login_failed ip={target_ip}"
        append_log(log)
        time.sleep(1)


def simulate_password_spraying():
    target_ip = "10.0.0.77"
    users = ["usr_alpha", "usr_beta", "usr_gamma", "usr_delta", "usr_omega"]
    print("\n[!] Simulating Password Spraying Attack from single IP...")
    for user in users:
        log = f"{get_current_time()} WARNING user={user} action=login_failed ip={target_ip}"
        append_log(log)
        time.sleep(1)


def simulate_dos_rate_limit():
    attacker_ip = "203.0.113.99"
    print("\n[!] Simulating High Request Rate / DoS...")
    for i in range(10):
        log = f"{get_current_time()} INFO user=guest action=api_request ip={attacker_ip}"
        append_log(log)
        time.sleep(0.3)


def simulate_sensitive_action():
    ip = "192.168.1.250"
    actions = ["privilege_escalation", "delete_logs", "disable_firewall"]
    action = random.choice(actions)
    print(f"\n[!] Simulating Sensitive Action: {action}...")
    log = f"{get_current_time()} CRITICAL user=hacker action={action} ip={ip}"
    append_log(log)


def main():
    print("==================================================")
    print("      Mini SIEM - Realistic Log Simulator         ")
    print("==================================================")
    print(f"Writing live events to: {LOG_FILE.resolve()}")
    print("Press Ctrl+C to stop simulation.\n")

    scenarios = [
        simulate_normal_traffic,
        simulate_normal_traffic,
        simulate_brute_force,
        simulate_normal_traffic,
        simulate_dos_rate_limit,
        simulate_password_spraying,
        simulate_normal_traffic,
        simulate_sensitive_action,
    ]

    try:
        while True:
            scenario = random.choice(scenarios)
            scenario()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Stopped log simulation.")


if __name__ == "__main__":
    main()

