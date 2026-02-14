from collections import Counter

LOG_FILE = "sample_auth.log"
FAIL_THRESHOLD = 3  # flag IPs with 3+ failed logins

def extract_value(token: str) -> str:
    # token looks like "IP=192.168.1.10" -> return "192.168.1.10"
    return token.split("=", 1)[1].strip()

def analyze_log(filepath: str) -> None:
    failed_ips = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Only care about failed attempts
            if "STATUS=FAILED" not in line:
                continue

            parts = line.split()
            ip_tokens = [p for p in parts if p.startswith("IP=")]

            if ip_tokens:
                ip = extract_value(ip_tokens[0])
                failed_ips.append(ip)

    counts = Counter(failed_ips)

    print(f"\nFailed login summary (threshold: {FAIL_THRESHOLD}+):\n")
    flagged = False
    for ip, count in counts.most_common():
        if count >= FAIL_THRESHOLD:
            flagged = True
            print(f"FLAG: {ip} -> {count} failed attempts")

    if not flagged:
        print("No IPs met the threshold.")

    print("\nAll failed attempts by IP:")
    for ip, count in counts.most_common():
        print(f"{ip}: {count}")

if __name__ == "__main__":
    analyze_log(LOG_FILE)
