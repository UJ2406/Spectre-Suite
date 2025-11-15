import whois
import dns.resolver
import requests
import os
import time
from concurrent.futures import ThreadPoolExecutor

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')
SUBDOMAINS_FILE = os.path.join(CURRENT_DIR, 'wordlists', 'subdomains.txt')

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV']

def load_wordlist(filepath):
    """Loads a wordlist from a .txt file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist {filepath}: {e}")
        return ['www', 'mail', 'admin'] # Fallback

SUBDOMAIN_WORDLIST = load_wordlist(SUBDOMAINS_FILE)

def check_subdomain(domain, subdomain):
    full_domain = f"{subdomain}.{domain}"
    try:
        requests.head(f"https://{full_domain}", timeout=3, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
        return full_domain
    except requests.RequestException:
        pass
    return None

def run_recon(domain):
    results = {
        'domain': domain, 
        'whois': {}, 
        'dns': {},
        'subdomains': []
    }
    
    try:
        w_info = whois.whois(domain)
        results['whois'] = {k: str(v) for k, v in w_info.items() if v}
    except Exception as e:
        results['whois'] = {'error': str(e)}

    resolver = dns.resolver.Resolver()
    for r_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, r_type)
            results['dns'][r_type] = [r.to_text() for r in answers]
        except Exception:
            results['dns'][r_type] = []
            
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_subdomain, domain, sub) for sub in SUBDOMAIN_WORDLIST]
        for future in futures:
            if future.result():
                results['subdomains'].append(future.result())
    
    results['subdomains'].sort()
    
    TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"domain_recon_{domain}_{TIMESTAMP}.txt"
    REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename)
    
    try:
        os.makedirs(DASHBOARD_DIR, exist_ok=True)
        with open(REPORT_FILE_TXT, 'w') as f:
            f.write("--- Domain Recon Report ---\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Domain: {domain}\n")
            f.write("--------------------------------------\n\n")

            f.write("--- FOUND SUBDOMAINS ---\n")
            if results['subdomains']:
                for sub in results['subdomains']:
                    f.write(f"[+] {sub}\n")
            else:
                f.write("No common subdomains found.\n")
            
            f.write("\n--- DNS RECORDS ---\n")
            for r_type, records in results['dns'].items():
                if records:
                    f.write(f"[*] {r_type}:\n")
                    for record in records:
                        f.write(f"    {record}\n")

            f.write("\n--- WHOIS INFO ---\n")
            if 'error' not in results['whois']:
                for key, value in results['whois'].items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write("Could not retrieve WHOIS data.\n")
        
        results['report_filename'] = report_filename
                
    except Exception as e:
        print(f"Error saving domain report: {e}")

    return results