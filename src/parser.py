def parse_log_line(line):
    parts = line.strip().split("|")

    if len(parts) != 4:
        return None

    timestamp = parts[0].strip()
    ip_address = parts[1].strip()
    event = parts[2].strip()
    username = parts[3].strip()

    return {
        "timestamp": timestamp,
        "ip": ip_address,
        "event": event,
        "username": username,
    }