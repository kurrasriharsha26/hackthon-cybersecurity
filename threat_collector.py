import requests
import json
import os

CVE_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # NVD API
DATA_FILE = "data/cve_data.json"

def fetch_cve_data(max_results=50):
    """Fetch CVE data from NVD API"""
    try:
        url = f"{CVE_FEED_URL}?resultsPerPage={max_results}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json().get("vulnerabilities", [])
        else:
            print(f"Error fetching CVE data: {response.status_code}")
            return []
    except Exception as e:
        print(f"Exception while fetching CVE data: {e}")
        return []

def save_cve_data(cve_items, filepath=DATA_FILE):
    """Save CVE data to JSON"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(cve_items, f, indent=4)
