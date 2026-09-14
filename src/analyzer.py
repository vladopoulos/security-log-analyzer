from parser import parse_log_line

LOG_FILE = "logs/sample_uth.log"

def load_logs(file_path):
    logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed_line = parse_log_line(line)

            if parsed_line is not None:
                logs.append(parsed_line)

    return logs

def main():
    logs = load_logs(LOG_FILE)

    successful_logins = 0
    failed_logins = 0
    failed_attempts_by_ip = {}

    for log in logs:
        if log["event"] == "LOGIN_SUCCESS":
            successful_logins += 1

        elif log["event"] == "LOGIN_FAILED":
            failed_logins += 1

            ip = log["ip"]

            if ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[ip] = 0

            failed_attempts_by_ip[ip] +=1

    print("Security Log Analyzer")
    print("=====================")
    print(f"Total log entries: {len(logs)}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {failed_logins}")

    print("\nFailed login attempts by IP:")

    for ip, count in failed_attempts_by_ip.items():
        print(f"{ip}: {count}")

if __name__ == "__main__" :
    main()