def print_summary(total_logs, successful_logins, failed_logins):
    print("Security Log Analyzer")
    print("=====================")
    print(f"Total log entries: {total_logs}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {failed_logins}")

def print_ip_analysis(failed_attempts_by_ip, suspicious_ips):
    print("\nFailed login attempts by IP:")

    for ip, timestamps in failed_attempts_by_ip.items():
        count = len(timestamps)

        if ip in suspicious_ips:
            print(f"{ip}: {count} failed attempts - SUSPICIOUS")
        else:
            print(f"{ip}: {count} failed attempts")

    print(f"\nSuspicious IPs detected: {len(suspicious_ips)}")

def print_username_analysis(failed_attempts_by_username):
    print("\nFailed login attempts by username:")

    for username, data in failed_attempts_by_username.items():
        count = data["count"]
        ips = data["ips"]

        print(f"{username}: {count} failed attempts from {len(ips)} IP(s)")

def print_suspicious_usernames(suspicious_usernames):
    print("\nSuspicious usernames:")

    if not suspicious_usernames:
        print("None detected")
        return

    for username in suspicious_usernames:
        print(f"{username}: SUSPICIOUS")