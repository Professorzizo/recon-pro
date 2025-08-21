
# 🔎 Bug Bounty Recon Automation

## 📌 Overview
This project automates the **Recon phase** of Bug Bounty hunting.  
It collects subdomains, endpoints, JavaScript files, parameters, sensitive URLs, and scans for common vulnerabilities using popular tools.

## 🚀 Features
- Collect subdomains (`subfinder`, `assetfinder`)
- Fetch URLs from multiple sources (`gau`, `waybackurls`, `gospider`)
- Detect live hosts (`httpx`)
- Extract JavaScript files and endpoints
- Find parameters for testing with `gf`
- Run automated vulnerability scans (`nuclei`, `dalfox`)
- Directory brute-forcing (`ffuf`)
- Organized results with timestamp
- Supports **cronjob for daily automation**
- Optional: send results to Telegram bot

## 🛠 Requirements
Install required tools and dependencies:

```bash
sudo apt update && sudo apt install -y jq curl wget unzip python3 python3-pip
