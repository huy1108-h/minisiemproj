from collector.log_reader import read_logs, parse_log
from detection.engine import run_detection


events = []

for line in read_logs("collector/sample.log"):
    event = parse_log(line)
    events.append(event)


alerts = run_detection(events)


for alert in alerts:
    print("🚨 SECURITY ALERT")
    print(alert)