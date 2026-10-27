# Threat Intelligence & OSINT Enrichment Tool

A Python-based cybersecurity tool that enriches IP addresses with threat intelligence from VirusTotal, classifies potential threats, and generates structured JSON reports.

## Features

- **IP Validation:** Validates IPv4 and IPv6 addresses and identifies invalid input.
- **Threat Intelligence Enrichment:** Retrieves IP reputation and analysis statistics from the VirusTotal API.
- **Threat Classification:** Classifies results as High, Medium, Low, No detections, or Unknown based on malicious detection counts.
- **JSON Reporting:** Saves enrichment results to a structured JSON report.
- **Error Handling:** Handles API errors, rate limits, and connection failures.
- **Automated Testing:** Uses Python's built-in `unittest` module to test core functionality without relying on live API requests.

## Technologies Used

- Python
- VirusTotal API v3
- Requests
- python-dotenv
- JSON
- unittest

## Project Structure

```text
threat_intel_enrichment/
├── threat_intel.py
├── test_threat_intel.py
├── sample_iocs.txt
├── requirements.txt
├── .env
├── .gitignore
└── reports/
    └── threat_report.json
```

## Requirements

- Python 3
- A VirusTotal account and API key
- Internet connectivity for live API lookups

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/deeyarajgor/threat_intel_enrichment.git
   cd threat_intel_enrichment
   ```

2. Install the dependencies:

   ```bash
   py -m pip install -r requirements.txt
   ```

   On Linux or macOS, use `python3` instead of `py` if necessary.

3. Create a `.env` file in the project root and add your VirusTotal API key:

   ```text
   VT_API_KEY=your_virustotal_api_key
   ```

   Replace the placeholder with your own API key. Never publish your actual key or commit the `.env` file to GitHub.

4. Add IP addresses to `sample_iocs.txt`, with one address per line.

## Usage

Run the tool from the project directory:

```bash
py threat_intel.py
```

The tool validates each input address, queries VirusTotal for valid IPs, displays the available reputation and detection statistics, and assigns a threat classification.

The generated report is saved to:

```text
reports/threat_report.json
```

The report contains the IP address, lookup status, reputation information, analysis statistics, and threat classification for successful lookups.

## Threat Classification

The tool uses the number of malicious detections reported by VirusTotal to assign an initial classification.

| Malicious detections | Classification |
|---:|---|
| 10 or more | High |
| 3–9 | Medium |
| 1–2 | Low |
| 0 | No detections |
| Missing statistics | Unknown |

These thresholds are defined by the project and are not official VirusTotal severity ratings. Classifications are intended to support investigation and should not be treated as definitive judgments about an IP address.

## Running Automated Tests

Run the test suite with:

```bash
py -m unittest discover -v
```

The tests cover IP validation, threat classification, input-file processing, and simulated API responses, including rate-limit handling. Mocked API tests do not require live VirusTotal requests.

## Limitations

- Results depend on the availability and freshness of VirusTotal's intelligence.
- API quotas and access permissions may restrict lookups.
- Zero malicious detections do not guarantee that an IP address is safe.
- Malicious detection counts are indicators for further investigation, not conclusive proof of malicious activity.
- The current implementation processes IP addresses rather than other indicator types, such as domains, URLs, or file hashes.
- Each run overwrites the previous JSON report.

## AI Use

AI assistance was used to support code development, debugging, test creation, and documentation. Implementation decisions and test results were reviewed during development.

## Ethical Use

This tool is intended for educational purposes, defensive security research, and authorised threat intelligence investigations. Use the VirusTotal API in accordance with its terms and applicable privacy requirements.


