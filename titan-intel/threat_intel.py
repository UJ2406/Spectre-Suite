import requests
import time
import re

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
cve_cache = {
    "data": None,
    "timestamp": 0
}

def get_cisa_vulns():
    """
    Fetches the CISA KEV feed and caches it for 1 hour.
    Returns the full list of vulnerability objects.
    """
    global cve_cache
    one_hour_ago = time.time() - 3600

    if cve_cache["data"] and cve_cache["timestamp"] > one_hour_ago:
        return cve_cache["data"]

    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        vuln_list = data.get("vulnerabilities", [])
        cve_cache["data"] = vuln_list
        cve_cache["timestamp"] = time.time()
        return vuln_list
    except requests.RequestException as e:
        print(f"Error fetching CISA feed: {e}")
        return []

def check_banner_for_vulns(banner, vulns_list):
    """
    Checks a service banner against the CISA vuln list.
    """
    if not banner or not vulns_list:
        return None

    banner_keywords = [b.lower() for b in re.findall(r'[\w.-]+', banner) if len(b) > 1]
    
    if not banner_keywords:
        return None

    for vuln in vulns_list:
        search_space = (vuln.get("vulnerabilityName", "") + " " + 
                        vuln.get("product", "")).lower()
        
        if all(keyword in search_space for keyword in banner_keywords):
            return vuln.get("cveID", "Match Found")
    
    return None