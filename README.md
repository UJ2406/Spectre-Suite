<div align="center">
  <h1>👻 Spectre Suite 👻</h1>
  <p>
    <b>A web-based OSINT & Cybersecurity Reconnaissance Dashboard.</b>
  </p>
  <p>
    <a href="https://www.python.org/"><img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white"></a>
    <a href="https://flask.palletsprojects.com/"><img alt="Flask" src="https://img.shields.io/badge/Flask-2.0%2B-black?logo=flask&logoColor=white"></a>
    <a href="https://github.com/YOUR-USERNAME/Spectre-Suite/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg"></a>
  </p>
</div>

---

## 🚀 Why Spectre Suite?

**Spectre Suite** is a centralized web dashboard designed for security professionals, researchers, and hobbyists. It replaces the need to run dozens of separate command-line scripts by integrating a powerful suite of OSINT and reconnaissance tools into a single, clean "glassmorphism" UI.

This dashboard allows you to gather intelligence on networks, domains, users, and websites, and then automatically cross-references your findings with live threat data.

## 📸 Project Gallery

| Main Dashboard | Scans Menu | Port Scanner (with CVEs) |
| :---: | :---: | :---: |
| ![Dashboard Screenshot](https://imgur.com/3mkc3Wf) | ![Scans Menu Screenshot](https://i.imgur.com/YOUR_IMAGE_URL.png) | ![Port Scan Screenshot](https://i.imgur.com/YOUR_IMAGE_URL.png) |
| **Domain Recon** | **Directory Scan** | **Reports Page** |
| ![Domain Recon Screenshot](https://i.imgur.com/YOUR_IMAGE_URL.png) | ![Directory Scan Screenshot](https://i.imgur.com/YOUR_IMAGE_URL.png) | ![Reports Page Screenshot](https://i.imgur.com/YOUR_IMAGE_URL.png) |

*(**Action:** Take screenshots of your app, upload them to [Imgur](https://imgur.com/upload), and replace the placeholder URLs!)*

---

## ✨ Features in Detail

| Tool | Icon | Function |
| :--- | :---: | :--- |
| **Live Threat Feed** | 🛡️ | Displays the latest Known Exploited Vulnerabilities (KEV) from the **CISA** feed on its own page. |
| **Port Scanner** | 💥 | Scans a target for open ports (top 100 or custom range) and identifies running services. |
| **Live CVE Intel** | 🤖 | **Automatically** cross-references found services (e.g., "Apache 2.4.41") with the CISA KEV database and flags active threats in the results. |
| **Domain Recon** | 🗺️ | Gathers full `WHOIS` data, enumerates all major `DNS` records, and finds active subdomains from a built-in wordlist. |
| **Social Media Scout** | 👥 | Finds user profiles across 20+ major social and tech sites (GitHub, Twitter, TryHackMe, etc.). |
| **Email Breach Check** | 📧 | Checks an email address against the **XposedOrNot** breach database (100% free, no API key required). |
| **Website Tech Scan** | ⚙️ | Identifies a website's technology stack (e.g., Nginx, React) and extracts interesting security headers. |
| **Directory Scan** | 📁 | Scans a web server for common hidden files and directories (e.g., `/admin`, `.env`). |
| **Report Generation** | 📜 | **Automatically** saves a detailed `.txt` report for every scan, available to view and download from the "Reports" page. |

---

## 🛠️ Tech Stack

* **Backend:** Python 3, Flask
* **Frontend:** HTML5, CSS3 (Glassmorphism), JavaScript (Fetch API)
* **Core Libraries:** `requests`, `whois`, `dnspython`, `builtwith`
* **Wordlists:** All wordlists (`subdomains.txt`, `common_paths.txt`, `social_sites.json`) are externalized for easy modification.

---

## 🚀 How to Run

Follow these steps to get the project running on your local machine.

### 1. Prerequisites

Make sure you have [Python 3](https://www.python.org/downloads/) and [Git](https://git-scm.com/downloads) installed.

### 2. Installation & Setup

**1. Clone the Repository:**
```bash
git clone [https://github.com/YOUR-USERNAME/Spectre-Suite.git](https://github.com/YOUR-USERNAME/Spectre-Suite.git)
cd Spectre-Suite
