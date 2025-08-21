
# 🔎 Bug Bounty Recon Automation

## 📌 Overview
This project automates the **Recon phase** of Bug Bounty hunting.  
It collects subdomains, endpoints, JavaScript files, parameters, sensitive URLs, and scans for common vulnerabilities using popular tools.



Professional Recon pipeline in Python with CLI options.

## Requirements

- Linux / WSL
- Python3 + pip
- Go installed

### Install all dependencies

```bash
bash install_requirements.sh




```bash

Usage:

python recon.py -d example.com -all
python recon.py -f targets.txt -s -u -j




-d : single domain

-f : file with domains

-s : get subdomains

-u : get URLs (gau + waybackurls)

-j : get JS files

-p : extract params

--php : extract PHP URLs

-g : run GF patterns (xss, sqli, lfi, rce, redirect)

--interest : save "interesting" subs and URLs

-all : run all steps




------------------------------------------------------------------------------------------------
All results saved in results/<target>/:

subs.txt : all subdomains

urls.txt : all URLs

php.txt : PHP URLs

params.txt : parameters

js-file.txt : JS files

gf_*.txt : GF pattern matches

interest-urls.txt / interest-subs.txt : interesting URLs / subs





