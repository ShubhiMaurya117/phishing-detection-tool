import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")


def check_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        response.raise_for_status()

        result = response.json()
        scan_id = result["data"]["id"]

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers,
            timeout=10
        )

        analysis.raise_for_status()

        stats = analysis.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return malicious, suspicious

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] VirusTotal request failed: {e}")
        return None, None

    except KeyError:
        print("[ERROR] Unexpected VirusTotal response format")
        return None, None
