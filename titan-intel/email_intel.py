import requests
import os
import time

# --- REPORT PATHS ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')

# --- NEW API ---
XPOSED_API_URL = "https://xposedornot.com/api_v1/exposed/"

def run_check(email):
    """
    Web-ready email breach check using XposedOrNot API.
    API Key is no longer needed.
    """
    if not email: 
        return {'error': 'Email is required.'}
        
    headers = {'User-Agent': 'Titan-Intel-Dashboard'}
    # The API expects the email as part of the URL
    url = f"{XPOSED_API_URL}{email}"
    results = {}
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            # 'breaches' key exists if pwned
            if 'breaches' in data:
                processed_breaches = []
                for breach_name, details in data['breaches'].items():
                    processed_breaches.append({
                        "name": breach_name,
                        "domain": details.get("domain", "N/A"),
                        "count": details.get("exposed_records_count", "N/A")
                    })
                results = {'email': email, 'status': 'pwned', 'breaches': processed_breaches}
            # 'error' key exists if not found
            elif 'error' in data:
                results = {'email': email, 'status': 'safe', 'breaches': []}
            else:
                results = {'email': email, 'status': 'safe', 'breaches': []}

        elif r.status_code == 404:
            # 404 also means not found
            results = {'email': email, 'status': 'safe', 'breaches': []}
        else:
            results = {'error': f'API returned status code: {r.status_code}'}
            
    except Exception as e:
        results = {'error': str(e)}

    # --- SAVE REPORT LOGIC ---
    if 'error' not in results:
        TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
        report_filename = f"email_check_{email}_{TIMESTAMP}.txt"
        REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename)
        
        try:
            os.makedirs(DASHBOARD_DIR, exist_ok=True)
            with open(REPORT_FILE_TXT, 'w') as f:
                f.write("--- Email Breach Check Report (XposedOrNot) ---\n")
                f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target Email: {email}\n")
                f.write("--------------------------------------\n\n")

                if results['status'] == 'safe':
                    f.write("Good news! This email was not found in any public breaches.\n")
                else:
                    f.write(f"[!!] PWNED! Found in {len(results['breaches'])} breaches:\n\n")
                    for breach in results['breaches']:
                        f.write(f"[*] Breach: {breach['name']}\n")
                        f.write(f"    Domain: {breach['domain']}\n")
                        f.write(f"    Exposed Records: {breach['count']}\n\n")
            
            results['report_filename'] = report_filename
                        
        except Exception as e:
            print(f"Error saving email report: {e}")

    return results