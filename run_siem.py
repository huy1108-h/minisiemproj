import argparse
import sys
from collector.log_reader import read_logs, tail_logs, parse_log
from detection.engine import RealtimeDetectionEngine, run_detection
from backend.app.database.repository import save_event, save_alert


def run_batch(file_path="collector/sample.log"):
    events = []
    print(f"[*] Reading logs from '{file_path}' (Batch Mode)...")

    for line in read_logs(file_path):
        event = parse_log(line)
        events.append(event)
        save_event(event)

    print(f"[+] Processed & saved {len(events)} events.")

    alerts = run_detection(events)
    for alert in alerts:
        save_alert(alert)
        print(f"[SECURITY ALERT] [{alert['severity']}] {alert['rule']}: {alert['message']}")

    print(f"[+] Saved {len(alerts)} alerts.")


def run_realtime(file_path="collector/sample.log"):
    print(f"[*] Starting Real-time SIEM Monitoring on '{file_path}'...")
    print("[*] Listening for incoming log events (Press Ctrl+C to stop)...\n")

    engine = RealtimeDetectionEngine()

    try:
        for line in tail_logs(file_path, poll_interval=0.5, start_from_beginning=False):
            event = parse_log(line)
            save_event(event)
            print(f"[EVENT] {event.get('timestamp')} | {event.get('level')} | action={event.get('action')} | ip={event.get('ip')}")

            alerts = engine.process_event(event)
            for alert in alerts:
                save_alert(alert)
                print(f"--> [SECURITY ALERT] [{alert['severity']}] {alert['rule']}: {alert['message']}")
    except KeyboardInterrupt:
        print("\n[*] Stopped SIEM monitoring.")


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM Log Processing & Threat Detection")
    parser.add_argument("--realtime", "-r", action="store_true", help="Run in continuous real-time tailing mode")
    parser.add_argument("--file", "-f", default="collector/sample.log", help="Path to target log file")
    args = parser.parse_args()

    if args.realtime:
        run_realtime(args.file)
    else:
        run_batch(args.file)


if __name__ == "__main__":
    main()