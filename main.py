import re

raw_logs = [
    "2026-01-12 13:48 INFO admin has logged into the server 10.10.189.90",
    "2026-04-20 00:20 INFO admin has logged into the server 10.10.209.78",
    "2026-05-30 18:29 WARNING admin access has been denied into the server 189.120.7.10",
    "2026-06-11 06:54 ERROR Unathorized acces into the server 176.111.90.1",
    "2026-02-29 03:26 ERROR Unathorized acces into the server 176.111.90.1",
]

def parse_logs(logs):
    parsed = []
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}) (\w+) (.+) into the server ([\d.]+)"
    for line in logs:
        match = re.match(pattern, line)
        if match:
            parsed.append({
                "timestamp": match.group(1),
                "level":match.group(2),
                "message":match.group(3),
                "ip":match.group(4)
            })
    return parsed
print(parse_logs(raw_logs))

print("\n")

def filter_suspicious(parse_logs):
   return [detection for detection in parse_logs if detection["level"] == "WARNING" or detection["level"] == "ERROR"]
print(filter_suspicious(parse_logs(raw_logs)))

print("\n")

def detect_brute_force(filter_suspicious):
    ip_count = {}
    for log in filter_suspicious:
        ip = log["ip"]
        ip_count[ip] = ip_count.get(ip, 0) + 1

    alerts = []
    for ip, count in ip_count.items():
        if count >= 2:
            alerts.append({
                "alert": "Unathorized acces detected",
                "ip":ip,
                "attempts":count
            })
    return alerts
print(detect_brute_force(filter_suspicious(parse_logs(raw_logs))))

print("\n")    

def report(alerts):
    if not alerts:
        print("No threats detected!")
    else:
        for alert in alerts:
            print(f"{alert['alert']} | IP:{alert['ip']} | ATTEMPTS:{alert['attempts']}")
report(detect_brute_force(filter_suspicious(parse_logs(raw_logs))))


