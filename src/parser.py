from datetime import datetime

def parse_log_line(line):
    parts = line.strip().split("|")

    if len(parts) != 4:
        return None

    timestamp = parts[0].strip()
    try:
        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    ip_address = parts[1].strip()
    event = parts[2].strip()
    username = parts[3].strip()

    return {
        "timestamp": timestamp,
        "ip": ip_address,
        "event": event,
        "username": username,
    }