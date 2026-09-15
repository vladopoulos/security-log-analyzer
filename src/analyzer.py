from parser import parse_log_line
from reporter import print_summary, print_ip_analysis, print_username_analysis, print_suspicious_usernames
from report_generator import generate_report

LOG_FILE = "logs/sample_uth.log"
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW_SECONDS = 60
MULTIPLE_IP_THRESHOLD = 3

def load_logs(file_path):
    logs = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                parsed_line = parse_log_line(line)

                if parsed_line is not None:
                    logs.append(parsed_line)

    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' was not found.")
        return []

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

def detect_multiple_ip_attack(ips):
    return len(ips) >= MULTIPLE_IP_THRESHOLD

def main():
    logs = load_logs(LOG_FILE)

    if not logs:
        return

    successful_logins = 0
    failed_logins = 0
    failed_attempts_by_ip = {}
    suspicious_ips = []
    suspicious_usernames = []
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
                failed_attempts_by_username[username] = {
                    "count": 0,
                    "ips": set()
                }
            
            failed_attempts_by_username[username]["count"] += 1
            failed_attempts_by_username[username]["ips"].add(ip)



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

    for username, data in failed_attempts_by_username.items():
        if detect_multiple_ip_attack(data["ips"]):
            suspicious_usernames.append(username)

    print_username_analysis(
        failed_attempts_by_username
    )

    print_suspicious_usernames(
        suspicious_usernames
    )

    generate_report(
        "reports/security_report.txt",
        len(logs),
        successful_logins,
        failed_logins,
        failed_attempts_by_ip,
        suspicious_ips,
        failed_attempts_by_username,
        suspicious_usernames
    )

if __name__ == "__main__" :
    main()