# Phishing Detection Tool
A Python-based cybersecurity tool that analyzes URLs to detect potential phishing attempts using rule-based heuristics and real-time threat intelligence from the VirusTotal API.

The tool assigns a risk score based on multiple indicators such as URL structure, suspicious patterns, and external threat database results.

## Features
- URL structure analysis (HTTPS, length, subdomains, keywords)
- Detection of suspicious patterns (login, verify, update, etc.)
- VirusTotal API integration for real-time threat intelligence
- Risk scoring system based on multiple indicators
- Automatic logging of scan results with timestamps
- Hybrid detection approach combining rule-based logic and API analysis

## Tech Stack
- Python
- Requests library
- VirusTotal API
- File handling for logging

## How it works
1. User inputs a URL
2. Tool analyzes the URL using predefined security rules
3. URL is checked against the VirusTotal API
4. Results are combined into a final risk score
5. Output is displayed and saved in a log file

## Installation & Setup

### Clone the repository
```bash
git clone https://github.com/ShubhiMaurya117/phishing-detection-tool.git
cd phishing-detection-tool 
```
### Install dependencies
```bash
pip install requests python-dotenv
```
### Set up environment variables
Create a .env file:
```bash
VT_API_KEY=your_virustotal_api_key
```
### Run the tool
```bash
python main.py
```

## Example Output
URL: http://example.com/login
Risk Level: Medium Risk (6/10)

Indicators:
- No HTTPS encryption
- Suspicious keyword detected: login
- Flagged by VirusTotal engines: 2

## Key Learning Outcomes
- API integration in Python
- Basic threat detection techniques
- URL analysis and pattern recognition
- File logging and structured output
- Cybersecurity fundamentals (phishing detection)

## Project Structure
```bash
phishing-detection-tool/
│
├── main.py
├── url_analyzer.py
├── virustotal.py
├── .gitignore
├── .env (not tracked)
└── scan_log.txt (ignored)
```
## Disclaimer
This tool is built for educational purposes only and should not be used as a production-grade security solution.

## Author
Shubhi Maurya  
B.Tech Electronics and Communication Engineering (ECE) Student  
Interested in Cybersecurity and Network Security  

GitHub: https://github.com/ShubhiMaurya117