import json
from pathlib import Path
import ipaddress #python's built in library to validate IP addresses
import os
import requests #sends HTTP requests to VirusTotal API
from dotenv import load_dotenv #loads variables from .env file

load_dotenv() #reads variables from .env file and makes them available in the environment

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

#the functions below are used to load IOCs from a text file, validate IP addresses, and retrieve reputation data from VirusTotal.
def load_iocs(filename):
    """Read IP addresses from a text file."""
    with open(filename, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()] 

def validate_ip(ip):
    """Return True if the value is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def lookup_ip(ip):
    """Retrieve IP reputation data from VirusTotal."""
    if not API_KEY:
        print("[ERROR] VT_API_KEY is missing. Check your .env file.")
        return None
    #prepare the request:
    headers = {"x-apikey": API_KEY}
    url = f"{BASE_URL}{ip}"
    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200: #check HTTP status code
            return response.json()
        #handle API errors:
        if response.status_code == 401:
            print("[ERROR] Invalid or unauthorized API key.")
        elif response.status_code == 403:
            print("[ERROR] Access forbidden. Check API access permissions.")
        elif response.status_code == 404:
            print(f"[ERROR] No report found for {ip}.")
        elif response.status_code == 429:
            print("[ERROR] API rate limit reached. Try again later.")
        else:
            print(f"[ERROR] VirusTotal returned HTTP {response.status_code}.")
    #handle connection errors and timeouts:
    except requests.RequestException as error:
        print(f"[ERROR] Request failed: {error}")

    return None


def main():
    """Validate input IPs and display VirusTotal reputation statistics."""
    print("Threat Intelligence & OSINT Enrichment Tool")
    print("-" * 50)

    try:
        iocs = load_iocs("sample_iocs.txt")
    except OSError as error:
        print(f"[ERROR] Could not read sample_iocs.txt: {error}")
        return
    report = []
    #process each IP address in the list:
    for ip in iocs:
        if not validate_ip(ip):
            print(f"[INVALID] {ip}")
            report.append({
                "ip": ip,
                "status": "invalid",
            })
            continue

        print(f"\n[LOOKUP] {ip}")
        result = lookup_ip(ip)

        if result is None:
            report.append({
                "ip": ip,
                "status": "lookup_failed",
            })
            continue
        #extract relevant data from the API response:
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        report.append({
            "ip": ip,
            "status": "success",
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": stats,
        })
        print(f"  Reputation: {attributes.get('reputation', 'N/A')}")
        print(f"  Malicious detections: {stats.get('malicious', 'N/A')}")
        print(f"  Suspicious detections: {stats.get('suspicious', 'N/A')}")
        print(f"  Harmless detections: {stats.get('harmless', 'N/A')}")
        print(f"  Undetected: {stats.get('undetected', 'N/A')}")
        reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_file = reports_dir / "threat_report.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\n[INFO] Report saved to {report_file}")


if __name__ == "__main__":
    main()

