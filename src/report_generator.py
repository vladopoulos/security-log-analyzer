def generate_report(
    output_file,
    total_logs,
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    suspicious_ips,
    failed_attempts_by_username,
    suspicious_usernames
):
    with open(output_file, "w", encoding="utf-8") as file:
        file.write("SECURITY LOG ANALYSIS REPORT\n")
        file.write("============================\n\n")

        file.write("Summary\n")
        file.write("-------\n")
        file.write(f"Total log entries: {total_logs}\n")
        file.write(f"Successful logins: {successful_logins}\n")
        file.write(f"Failed logins: {failed_logins}\n")

        file.write("Suspicious IPs\n")
        file.write("--------------\n")

        if not suspicious_ips:
            file.write("None detected\n\n")
        else:
            for ip in suspicious_ips:
                count = len(failed_attempts_by_ip[ip])
                file.write(
                    f"{ip}: {count} failed attempts within "
                    f"the configured time window\n"
                )

            file.write("\n")

        file.write("Suspicious Usernames\n")
        file.write("--------------------\n")
        
        if not suspicious_usernames:
            file.write("None detected\n\n")
        else:
            for username in suspicious_usernames:
                data = failed_attempts_by_username[username]
                count = data["count"]
                ip_count = len(data["ips"])

                file.write(
                        f"{username}: {count} failed attempts from "
                        f"{ip_count} different IPs\n"
                    )
        
            file.write("\n")

        file.write("Overall Findings\n")
        file.write("----------------\n")

        if suspicious_ips:
            file.write("Potential brute-force activity detected.\n")

        if suspicious_usernames:
            file.write("Multiple IP activity detected for suspicious usernames.\n")

        if not suspicious_ips and not suspicious_usernames:
            file.write("No suspicious activity detected.\n")