from collections import defaultdict

LOG_FILE = "sample_logs.txt"
OUTPUT_FILE = "suspicious_ips.txt"

THRESHOLD = 4

failed_attempts = defaultdict(int)

print("\n[+] Monitoring Login Attempts...\n")

try:
    with open(LOG_FILE, "r") as file:

        for line in file:
            parts = line.strip().split()

            if len(parts) < 4:
                continue

            status = parts[2]
            ip = parts[3]

            if status == "FAILED_LOGIN":
                failed_attempts[ip] += 1

except FileNotFoundError:
    print("[-] Log file not found.")
    exit()

suspicious_ips = []

print("[+] Failed Login Attempt Summary:\n")

for ip, count in failed_attempts.items():
    print(f"{ip} --> {count} failed attempts")

    if count >= THRESHOLD:
        suspicious_ips.append((ip, count))

print("\n[+] Checking for Brute Force Activity...\n")

if suspicious_ips:

    with open(OUTPUT_FILE, "w") as out:
        out.write("Suspicious IP Addresses\n")
        out.write("=" * 30 + "\n")

        for ip, count in suspicious_ips:
            alert = f"{ip} --> {count} failed login attempts\n"

            print("[ALERT]", alert.strip())

            out.write(alert)

    print(f"\n[+] Suspicious IPs saved to {OUTPUT_FILE}")

else:
    print("[+] No brute force activity detected.")