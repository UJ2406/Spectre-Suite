import requests
import os
import time
import json
from concurrent.futures import ThreadPoolExecutor

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')
SITES_FILE = os.path.join(CURRENT_DIR, 'wordlists', 'social_sites.json')

def load_sites_json(filepath):
    """Loads the site list from a .json file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return {"GitHub": "https://github.com/{}"} # Fallback

SOCIAL_SITES = load_sites_json(SITES_FILE)

def check_site(site_name, url_format, username):
    url = url_format.format(username)
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return {'site': site_name, 'url': url}
    except requests.RequestException:
        pass
    return None

def run_scout(username):
    if not username: 
        return {'error': 'No username provided.'}
    
    found = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_site, k, v, username) for k, v in SOCIAL_SITES.items()]
        for future in futures:
            res = future.result()
            if res: 
                found.append(res)
                
    results = {'username': username, 'results': found}
    
    TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"social_scout_{username}_{TIMESTAMP}.txt"
    REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename)
    
    try:
        os.makedirs(DASHBOARD_DIR, exist_ok=True)
        with open(REPORT_FILE_TXT, 'w') as f:
            f.write("--- Social Media Scout Report ---\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Username: {username}\n")
            f.write("--------------------------------------\n\n")

            if results['results']:
                f.write(f"Found {len(results['results'])} matching accounts:\n\n")
                for account in results['results']:
                    f.write(f"[+] {account['site']}: {account['url']}\n")
            else:
                f.write("No matching accounts found on common sites.\n")
        
        results['report_filename'] = report_filename
                
    except Exception as e:
        print(f"Error saving social scout report: {e}")
        
    return results