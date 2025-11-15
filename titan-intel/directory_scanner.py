import requests
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')
PATHS_FILE = os.path.join(CURRENT_DIR, 'wordlists', 'common_paths.txt')

def load_wordlist(filepath):
    """Loads a wordlist from a .txt file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist {filepath}: {e}")
        return ['admin', 'login', 'robots.txt'] # Fallback

COMMON_PATHS = load_wordlist(PATHS_FILE)

def clean_filename(url):
    name = re.sub(r'https?://', '', url)
    name = re.sub(r'[^\w\.-]', '_', name)
    return name

def check_path(base_url, path):
    url = f"{base_url}/{path}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=4, allow_redirects=False)
        if response.status_code in [200, 403, 301, 302]:
            return {'status_code': response.status_code, 'url': url}
    except requests.RequestException:
        pass
    return None

def run_scan(url):
    if not (url.startswith('http://') or url.startswith('https://')):
        url = f"https://{url}"
        
    found_paths = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_path, url, path) for path in COMMON_PATHS]
        for future in futures:
            result = future.result()
            if result:
                found_paths.append(result)
    
    found_paths.sort(key=lambda x: x['status_code'])
    results = {'target': url, 'results': found_paths}
    
    TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
    safe_url_name = clean_filename(url)
    report_filename = f"dir_scan_{safe_url_name}_{TIMESTAMP}.txt"
    REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename)
    
    try:
        os.makedirs(DASHBOARD_DIR, exist_ok=True)
        with open(REPORT_FILE_TXT, 'w') as f:
            f.write("--- Directory Scan Report ---\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {url}\n")
            f.write("--------------------------------------\n\n")

            if results['results']:
                f.write(f"Found {len(results['results'])} interesting paths:\n\n")
                for path in results['results']:
                    f.write(f"[+] Status {path['status_code']}: {path['url']}\n")
            else:
                f.write("No common directories or files found.\n")
        
        results['report_filename'] = report_filename
                        
    except Exception as e:
        print(f"Error saving directory scan report: {e}")

    return results