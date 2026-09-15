from parser import parse_log_line
from reporter import print_summary, print_ip_analysis, print_username_analysis

LOG_FILE = "logs/sample_uth.log"
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW_SECONDS = 60

def load_logs(file_path):
    logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed_line = parse_log_line(line)

            if parsed_line is not None:
                logs.append(parsed_line)

    return logs

def detect_brute_force(timestamps):
    if len(timestamps) < BRUTE_FORCE_THRESHOLD:
        return False

    for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
        start_time = timestamps[i]
        end_time = timestamps[i + BRUTE_FORCE_THRESHOLD - 1]

        time_difference = (end_time - start_time).total_seconds()

        if time_difference <= BRUTE_FORCE_WINDOW_SECONDS:
            return True

    return False

def main():
    logs = load_logs(LOG_FILE)

    successful_logins = 0
    failed_logins = 0
    failed_attempts_by_ip = {}
    suspicious_ips = []
    failed_attempts_by_username = {}

    for log in logs:
        if log["event"] == "LOGIN_SUCCESS":
            successful_logins += 1

        elif log["event"] == "LOGIN_FAILED":
            failed_logins += 1

            ip = log["ip"]

            if ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[ip] = []

            failed_attempts_by_ip[ip].append(log["timestamp"])

            username = log["username"]
            
            if username not in failed_attempts_by_username:
                failed_attempts_by_username[username] = 0
            
            failed_attempts_by_username[username] += 1



    print_summary(
        len(logs),
        successful_logins,
        failed_logins
    )

    for ip, timestamps in failed_attempts_by_ip.items():
        if detect_brute_force(timestamps):
            suspicious_ips.append(ip)

    print_ip_analysis(
        failed_attempts_by_ip,
        suspicious_ips
    )

    print_username_analysis(
        failed_attempts_by_username
    )

if __name__ == "__main__" :
    main()