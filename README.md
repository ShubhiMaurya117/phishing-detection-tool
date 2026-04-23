# Phishing Detection Tool

A Python-based URL analyser that detects phishing indicators and checks URLs against the VirusTotal threat database.

## Features
- Analyses URLs for suspicious patterns (missing HTTPS, hyphens, suspicious keywords, long URLs)
- Integrates VirusTotal API to check against 70+ antivirus engines
- Assigns a risk score out of 10 with a risk level (Safe / Low / Medium / High)
- Logs all scan results with timestamps to a local file

## Tech Stack
- Python
- Requests library
- VirusTotal API

## How to Run
1. Clone the repository
2. Install dependencies: `pip install requests`
3. Add your VirusTotal API key in the script
4. Run: `python phishing_tool.py`
5. Paste any URL when prompted

## Example Output
URL: http://free-prize-win.com/login
Risk Level: High Risk (7/10)
VirusTotal: 0 malicious, 0 suspicious detections
Warnings:
  - No HTTPS
  - Hyphens in URL
  - Suspicious keywords found

## Author
Shubhi Maurya — github.com/ShubhiMaurya117
