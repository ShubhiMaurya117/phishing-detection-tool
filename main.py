import os
import requests
import datetime
from urllib.parse import urlparse
from virustotal import check_virustotal
from url_analyzer import check_url_features
API_KEY = os.getenv("VT_API_KEY")


def validate_url(url):
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return False

    return True

def calculate_risk(score):
    if score <= 20:
        return "Low Risk"

    elif score <= 50:
        return "Medium Risk"

    return "High Risk"


def save_log(url, score, risk, warnings, malicious, suspicious):
    with open("scan_log2.txt", "a") as f:

        f.write(f"\n{'=' * 50}\n")
        f.write(
            f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        f.write(f"URL: {url}\n")
        f.write(f"Risk Score: {score}/100\n")
        f.write(f"Risk Level: {risk}\n")

        f.write(
            f"VirusTotal: {malicious} malicious, "
            f"{suspicious} suspicious\n"
        )

        f.write(
            f"Warnings: "
            f"{', '.join(warnings) if warnings else 'None'}\n"
        )


# MAIN PROGRAM

url = input("Paste URL to analyze: ").strip()

if not validate_url(url):
    print("Invalid URL format.")
    exit()

print("\n[+] Analyzing URL features...")
warnings, score = check_url_features(url)

print("[+] Checking VirusTotal intelligence...")

malicious, suspicious = check_virustotal(url)

if malicious is not None:

    if malicious > 0:
        score += 40
        warnings.append(
            f"Flagged malicious by {malicious} VirusTotal engines"
        )

    elif suspicious > 0:
        score += 20
        warnings.append(
            f"Marked suspicious by {suspicious} VirusTotal engines"
        )

score = min(score, 100)

risk = calculate_risk(score)

print("\n========== ANALYSIS REPORT ==========")
print(f"URL: {url}")
print(f"Risk Score: {score}/100")
print(f"Threat Level: {risk}")

if malicious is not None:
    print(
        f"VirusTotal Results: "
        f"{malicious} malicious | "
        f"{suspicious} suspicious"
    )

print("\nIndicators Detected:")

if warnings:
    for warning in warnings:
        print(f"[!] {warning}")

else:
    print("No major indicators detected.")

save_log(
    url,
    score,
    risk,
    warnings,
    malicious,
    suspicious
)

print("\n[+] Scan result saved to log file.")