import requests
import datetime

API_KEY = "4594df177398654785138c45a0c6df51f8ab6944d0dc7e9f570532e86feb0731"

def check_url_features(url):
    warnings = []
    score = 0

    if "https" not in url:
        warnings.append("No HTTPS")
        score += 3

    if "-" in url:
        warnings.append("Hyphens in URL")
        score += 2

    if len(url) > 50:
        warnings.append("URL is very long")
        score += 1

    if "login" in url or "verify" in url or "update" in url:
        warnings.append("Suspicious keywords found")
        score += 2

    if url.count(".") > 3:
        warnings.append("Too many subdomains")
        score += 3

    return warnings, score

def check_virustotal(url):
    headers = {"x-apikey": API_KEY}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    
    if response.status_code == 200:
        result = response.json()
        scan_id = result["data"]["id"]
        
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        stats = analysis.json()["data"]["attributes"]["stats"]
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return malicious, suspicious
    else:
        return None, None

def save_log(url, score, risk, warnings, malicious, suspicious):
    with open("scan_log.txt", "a") as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"URL: {url}\n")
        f.write(f"Risk Level: {risk} ({score}/10)\n")
        f.write(f"VirusTotal: {malicious} malicious, {suspicious} suspicious\n")
        f.write(f"Warnings: {', '.join(warnings) if warnings else 'None'}\n")

# MAIN
url = input("Paste a URL to check: ")

print("\nChecking URL features...")
warnings, score = check_url_features(url)

print("Checking VirusTotal database...")
malicious, suspicious = check_virustotal(url)

if malicious is not None:
    if malicious > 0:
        score += 5
        warnings.append(f"Flagged by {malicious} VirusTotal engines")
    elif suspicious > 0:
        score += 2
        warnings.append(f"Marked suspicious by {suspicious} VirusTotal engines")

score = min(score, 10)

if score == 0:
    risk = "Safe"
elif score <= 3:
    risk = "Low Risk"
elif score <= 6:
    risk = "Medium Risk"
else:
    risk = "High Risk"

print(f"\n--- Phishing Check Results ---")
print(f"URL: {url}")
print(f"Risk Level: {risk} ({score}/10)")

if malicious is not None:
    print(f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections")

if len(warnings) == 0:
    print("No warnings found!")
else:
    print(f"Warnings ({len(warnings)}):")
    for w in warnings:
        print(f"  - {w}")

save_log(url, score, risk, warnings, malicious, suspicious)
print("\nResult saved to scan_log.txt")