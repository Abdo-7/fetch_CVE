import requests
import time
from datetime import datetime, timedelta, UTC

def fetch_cves_from_vulners():
    """ Fetch only new CVEs from Vulners """
    url = "https://vulners.com/api/v3/burp/software/?query=CVE-2024-*"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json().get("data", {}).get("search", [])
        new_cves = []
        today = datetime.now(UTC).date()
        
        for item in data:
            pub_date = item.get("_source", {}).get("published", "")
            if pub_date:
                pub_date = datetime.strptime(pub_date, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).date()
                if pub_date == today:
                    new_cves.append(item)
        
        return new_cves
    else:
        print("Failed to fetch CVEs from Vulners")
        return []

def main():
    cves = fetch_cves_from_vulners()
    
    if not cves:
        print("No new CVEs found today.")
    
    for cve in cves:
        print(cve.get("_source", {}).get("id", "Unknown ID"), "-", cve.get("_source", {}).get("description", "No description"))
        time.sleep(1)  # Avoid excessive API requests

if __name__ == "__main__":
    main()


