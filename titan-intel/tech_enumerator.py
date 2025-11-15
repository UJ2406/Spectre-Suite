import builtwith
import requests
import os
import time
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')

INTERESTING_HEADERS = [
    'Server', 'X-Powered-By', 'X-AspNet-Version', 'Set-Cookie', 
    'Content-Security-Policy', 'Strict-Transport-Security'
]

def clean_filename(url):
    """Removes http/https and replaces special chars to make a safe filename."""
    name = re.sub(r'https?://', '', url) # Remove http/https
    name = re.sub(r'[^\w\.-]', '_', name) # Replace non-alphanumeric chars with _
    return name

def run_enum(url):
    if not (url.startswith('http://') or url.startswith('https://')):
        url = f"https://{url}"
        
    results = {'url': url, 'tech_stack': {}, 'headers': {}}
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5)
        
        tech = builtwith.parse(url, html=response.text)
        results['tech_stack'] = tech
        
        for header in INTERESTING_HEADERS:
            if header in response.headers:
                results['headers'][header] = response.headers[header]
                
        if not results['tech_stack'] and not results['headers']:
            results = {'url': url, 'error': 'Could not identify any technologies or headers.'}
        
    except Exception as e:
        results = {'url': url, 'error': f'Failed to analyze website: {str(e)}'}

    TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
    safe_url_name = clean_filename(url) # <-- NEW: Create safe name
    report_filename = f"tech_scan_{safe_url_name}_{TIMESTAMP}.txt" # <-- UPDATED
    REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename)
    
    try:
        os.makedirs(DASHBOARD_DIR, exist_ok=True)
        with open(REPORT_FILE_TXT, 'w') as f:
            f.write("--- Website Tech Scan Report ---\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {url}\n")
            f.write("--------------------------------------\n\n")

            if 'error' in results:
                f.write(f"Scan failed: {results['error']}\n")
            else:
                f.write("--- INTERESTING HEADERS ---\n")
                if results['headers']:
                    for key, value in results['headers'].items():
                        f.write(f"{key}: {value}\n")
                else:
                    f.write("No interesting headers found.\n")
                
                f.write("\n--- TECHNOLOGY STACK ---\n")
                if results['tech_stack']:
                    for key, value in results['tech_stack'].items():
                        f.write(f"{key}: {', '.join(value)}\n")
                else:
                    f.write("No technologies identified.\n")
        
        results['report_filename'] = report_filename
                        
    except Exception as e:
        print(f"Error saving tech scan report: {e}")

    return results