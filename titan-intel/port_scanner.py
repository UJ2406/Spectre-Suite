import socket
import sys
import os
import time
import json
import re
from concurrent.futures import ThreadPoolExecutor

try:
    import threat_intel
except ImportError:
    print("Error: threat_intel.py not found. Make sure it's in the titan-intel folder.")
    sys.exit(1)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(CURRENT_DIR, '..', 'Shiganshina_Dashboard', 'static', 'reports')

def parse_ports(port_range):
    if not port_range:
        return [
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 113, 119, 123, 135, 137, 
            138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 513, 514, 515, 
            548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1080, 1194, 1352, 1433, 
            1434, 1521, 1701, 1723, 1761, 1812, 1813, 2000, 2049, 2082, 2083, 2086, 
            2087, 2121, 2483, 2484, 3000, 3128, 3306, 3389, 4000, 4443, 5000, 5060, 
            5061, 5190, 5357, 5432, 5631, 5800, 5900, 6000, 6001, 6667, 8000, 8008, 
            8080, 8081, 8443, 8888, 9000, 9090, 9100, 9418, 10000, 32768
        ]
    ports = []
    try:
        if ',' in port_range:
            parts = port_range.split(',')
            for part in parts:
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        elif '-' in port_range:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(port_range))
        return list(set(ports))
    except Exception:
        return [80, 443, 22]

def grab_banner(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, port))
        banner_bytes = sock.recv(1024)
        sock.close()
        banner_str = banner_bytes.decode('utf-8', errors='ignore').strip()
        return banner_str if banner_str else "Service detected, but no banner returned."
    except Exception:
        return "No banner (Error or Timeout)"

def check_port_and_banner(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = grab_banner(target_ip, port)
            return (port, banner)
    except socket.error:
        pass
    finally:
        sock.close()
    return None

def run_scan(target_host, port_range_str):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        return {'error': f"Cannot resolve hostname: {target_host}"}

    cisa_vulns_list = threat_intel.get_cisa_vulns()
    ports_to_scan = parse_ports(port_range_str)
    open_ports_info = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_port_and_banner, target_ip, port): port for port in ports_to_scan}
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports_info.append(result)

    open_ports_info.sort()
    
    processed_results = []
    for port, banner in open_ports_info:
        found_cve = threat_intel.check_banner_for_vulns(banner, cisa_vulns_list)
        processed_results.append({'port': port, 'banner': banner, 'cve': found_cve})
    
    scan_data = {
        'target': target_host,
        'target_ip': target_ip,
        'results': processed_results
    }
    
    TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"port_scan_{TIMESTAMP}.txt" 
    REPORT_FILE_TXT = os.path.join(DASHBOARD_DIR, report_filename) 

    try:
        os.makedirs(DASHBOARD_DIR, exist_ok=True)
        with open(REPORT_FILE_TXT, 'w') as f:
            f.write("--- Spectre Suite Scan Report ---\n") # <-- CHANGED HERE
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {target_host} ({target_ip})\n")
            f.write("--------------------------------------\n\n")
            f.write("Open Ports & Services:\n\n")
            
            if not processed_results:
                f.write("No open ports found in the specified range.\n")
            
            for item in processed_results:
                f.write(f"[+] Port: {item['port']}\n")
                f.write(f"    Banner: {item['banner']}\n")
                if item['cve']:
                    f.write(f"    [!!] VULNERABILITY FOUND: {item['cve']}\n")
                f.write("\n")
        
        scan_data['message'] = "Scan complete."
        scan_data['report_filename'] = report_filename
    except Exception as e:
        scan_data['message'] = f"Scan complete, but failed to save report: {e}"
        
    return scan_data