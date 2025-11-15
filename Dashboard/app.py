from flask import Flask, render_template, request, jsonify, url_for
import sys
import os
import requests
import time

# --- 1. SETUP PATH TO FIND titan-intel ---
script_dir = os.path.dirname(os.path.realpath(__file__))
titan_intel_path = os.path.join(script_dir, '..', 'titan-intel')
sys.path.append(titan_intel_path)

# --- 2. IMPORT YOUR MODULES ---
try:
    import port_scanner
    import domain_recon
    import social_scout
    import email_intel
    import tech_enumerator
    import threat_intel
    import directory_scanner
except ImportError as e:
    print(f"FATAL ERROR: Could not import scanner modules: {e}")
    print(f"Please ensure 'titan-intel' folder is at: {titan_intel_path}")
    sys.exit(1)

# --- CONFIGURATION ---
REPORTS_DIR = os.path.join(script_dir, 'static', 'reports')

app = Flask(__name__)
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- Main Page Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reports')
def reports():
    report_files = []
    try:
        files = os.listdir(REPORTS_DIR)
        report_files = [f for f in files if f.endswith('.txt')]
        report_files.sort(reverse=True)
    except Exception as e:
        print(f"Error reading reports directory: {e}")
    return render_template('reports.html', reports=report_files)

@app.route('/live_feed')
def live_feed():
    return render_template('live_feed.html')

# --- Scan Menu Route ---
@app.route('/scans')
def scans():
    return render_template('scans.html')

# --- Dedicated Scan Pages ---
@app.route('/scans/port')
def scan_port():
    return render_template('scan_port.html')

@app.route('/scans/domain')
def scan_domain():
    return render_template('scan_domain.html')

@app.route('/scans/social')
def scan_social():
    return render_template('scan_social.html')

@app.route('/scans/email')
def scan_email():
    return render_template('scan_email.html')

@app.route('/scans/tech')
def scan_tech():
    return render_template('scan_tech.html')

@app.route('/scans/directory')
def scan_directory():
    return render_template('scan_directory.html')

# --- API ENDPOINTS ---

@app.route('/api/start-port-scan', methods=['POST'])
def handle_port_scan():
    return jsonify(port_scanner.run_scan(request.form['target'], request.form['ports']))

@app.route('/api/start-domain-recon', methods=['POST'])
def handle_domain_recon():
    return jsonify(domain_recon.run_recon(request.form['domain']))

@app.route('/api/start-social-scout', methods=['POST'])
def handle_social_scout():
    return jsonify(social_scout.run_scout(request.form['username']))

@app.route('/api/start-email-check', methods=['POST'])
def handle_email_check():
    return jsonify(email_intel.run_check(request.form['email']))

@app.route('/api/start-tech-enum', methods=['POST'])
def handle_tech_enum():
    return jsonify(tech_enumerator.run_enum(request.form['url']))

@app.route('/api/start-dir-scan', methods=['POST'])
def handle_dir_scan():
    return jsonify(directory_scanner.run_scan(request.form['url']))

@app.route('/api/get-cve-feed')
def get_cve_feed():
    try:
        vuln_list = threat_intel.get_cisa_vulns()
        sorted_vulns = sorted(vuln_list, 
                              key=lambda x: x.get('dateAdded', ''), 
                              reverse=True)
        top_10_vulns = sorted_vulns[:10]
        return jsonify(top_10_vulns)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Main entry point ---
if __name__ == "__main__":
    print("[*] Starting Spectre Suite...") # <-- NAME CHANGED HERE
    print(f"[*] Titan-Intel modules loaded from: {titan_intel_path}")
    app.run(debug=True, port=5000)