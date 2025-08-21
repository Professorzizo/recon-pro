#!/usr/bin/env python3
"""
pro_recon.py

Professional Recon pipeline (single-file) that orchestrates common recon CLIs and Python tools:
- Runs: subfinder, assetfinder, crt.sh query
- Optionally runs: gau, waybackurls, gf patterns (xss, sqli, lfi, rce, redirect)
- Collects interesting endpoints (login, rest, password, update)
- Collects 403 URLs
- Extracts JS files
- Consolidates and deduplicates subdomains and URLs
- Checks alive subdomains and URLs (async, fast)
- Extracts PHP URLs to php.txt and parameters to params files
- Installs missing tools and Python dependencies automatically
- Uses rich for colored UI and setproctitle to set process name (optional)
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Set

console_imported = False
try:
    import requests
    import httpx
    from rich.console import Console
    from rich.panel import Panel
    console_imported = True
except ImportError:
    pass

console = Console() if console_imported else None

# ---- check and install required tools ----
REQUIRED_CLI_TOOLS = ['subfinder', 'assetfinder', 'gau', 'waybackurls', 'gf']
PYTHON_LIBS = ['requests', 'httpx', 'rich']

def install_missing():
    for lib in PYTHON_LIBS:
        try:
            __import__(lib)
        except ImportError:
            print(f"[!] Installing missing Python library: {lib}")
            subprocess.run([sys.executable, '-m', 'pip', 'install', lib])

    for tool in REQUIRED_CLI_TOOLS:
        if shutil.which(tool) is None:
            print(f"[!] CLI tool missing: {tool}. Please install it manually or via package manager.")

install_missing()

# ---- rest of imports ----
try:
    from setproctitle import setproctitle
except Exception:
    setproctitle = None

console = Console()

# ---- utilities ----

def now_str():
    return datetime.utcnow().strftime('%Y%m%d_%H%M%S')

def run_cmd(cmd: List[str], capture_output=True, check=False, shell=False):
    try:
        if shell:
            res = subprocess.run(' '.join(cmd), shell=True, capture_output=capture_output, text=True)
        else:
            res = subprocess.run(cmd, capture_output=capture_output, text=True)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
        return res
    except Exception as e:
        console.log(f"[red]Command failed:[/red] {cmd} -> {e}")
        return None

def which(cmdname: str) -> bool:
    return shutil.which(cmdname) is not None

# ---- collectors (subdomains, URLs, JS, 403, interesting endpoints) ----

def run_subfinder(domain: str, out_file: Path):
    if not which('subfinder'):
        console.log('[yellow]subfinder not found, skipping subfinder step[/yellow]')
        return
    console.log('[cyan]Running subfinder...[/cyan]')
    res = run_cmd(['subfinder', '-d', domain, '-silent'])
    if res and res.stdout:
        out_file.write_text(res.stdout)


def run_assetfinder(domain: str, out_file: Path):
    if not which('assetfinder'):
        console.log('[yellow]assetfinder not found, skipping assetfinder step[/yellow]')
        return
    console.log('[cyan]Running assetfinder...[/cyan]')
    res = run_cmd(['assetfinder', '--subs-only', domain])
    if res and res.stdout:
        out_file.write_text(res.stdout)


def query_crtsh(domain: str) -> Set[str]:
    console.log('[cyan]Querying crt.sh...[/cyan]')
    domains = set()
    url = f'https://crt.sh/?q=%25{domain}&output=json'
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            try:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value') or entry.get('common_name')
                    if name:
                        for line in str(name).split('\n'):
                            line = line.strip().lstrip('*.')
                            if line.endswith(domain):
                                domains.add(line)
            except Exception as e:
                console.log(f'[red]crt.sh parse error:[/red] {e}')
    except Exception as e:
        console.log(f'[red]crt.sh request failed:[/red] {e}')
    return domains


def run_gau(domain: str, out_file: Path):
    if not which('gau'):
        console.log('[yellow]gau not found, skipping gau step[/yellow]')
        return
    console.log('[cyan]Running gau (getallurls)...[/cyan]')
    res = run_cmd(['gau', domain])
    if res and res.stdout:
        out_file.write_text(res.stdout)


def run_waybackurls(domain: str, out_file: Path):
    if not which('waybackurls'):
        console.log('[yellow]waybackurls not found, skipping waybackurls step[/yellow]')
        return
    console.log('[cyan]Running waybackurls...[/cyan]')
    p = subprocess.Popen(['waybackurls', domain], stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(timeout=120)
    if out:
        out_file.write_text(out)

# ---- extract interesting endpoints and JS ----

def extract_interesting(urls: List[str], out_file: Path):
    keywords = ['login', 'rest', 'password', 'update']
    interesting = [u for u in urls if any(k in u.lower() for k in keywords)]
    if interesting:
        out_file.write_text('\n'.join(sorted(set(interesting))))


def extract_js_files(urls: List[str], out_file: Path):
    js_files = [u for u in urls if u.lower().endswith('.js')]
    if js_files:
        out_file.write_text('\n'.join(sorted(set(js_files))))
