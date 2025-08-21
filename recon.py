#!/usr/bin/env python3
import argparse, subprocess, shutil, os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from urllib.parse import urlparse, parse_qs

console = Console()

# ---- Utilities ----
def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.stdout.strip() if res.stdout else ""
    except Exception as e:
        console.log(f"[red]Command failed:[/red] {cmd} -> {e}")
        return ""

def install_tools():
    tools = ["subfinder", "assetfinder", "gau", "waybackurls", "gf", "httpx"]
    for t in tools:
        if shutil.which(t) is None:
            console.log(f"[yellow]{t} not found. Installing...[/yellow]")
            if t=="httpx":
                run_cmd("go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            elif t=="gf":
                run_cmd("go install github.com/tomnomnom/gf@latest")
                run_cmd("mkdir -p ~/.gf && cp -r $(go env GOPATH)/pkg/mod/github.com/tomnomnom/gf*/examples/* ~/.gf/")
            else:
                run_cmd(f"go install github.com/projectdiscovery/{t}/v2/cmd/{t}@latest")
    console.log("[green]All required tools installed![/green]")

# ---- Collectors ----
def get_subs(domain, outdir):
    out_file = outdir/"subs.txt"
    live_file = outdir/"live-subs.txt"
    all_subs = set()
    for t in ["subfinder", "assetfinder"]:
        if shutil.which(t):
            console.log(f"[cyan]Running {t}...[/cyan]")
            res = run_cmd(f"{t} -d {domain} -silent")
            if res:
                all_subs.update(res.splitlines())
    if all_subs:
        out_file.write_text("\n".join(sorted(all_subs)))
        console.log(f"[green]All subs saved -> {out_file}[/green]")
    else:
        console.log(f"[yellow]No subs found for {domain}[/yellow]")

    # Check live subs
    if all_subs and shutil.which("httpx"):
        console.log("[cyan]Checking live subdomains...[/cyan]")
        live_res = run_cmd(f"echo '{chr(10).join(all_subs)}' | httpx -silent -timeout 10")
        live_subs = sorted(set(live_res.splitlines()))
        live_file.write_text("\n".join(live_subs))
        console.log(f"[green]Live subs saved -> {live_file}[/green]")
    return live_file

def get_urls(subs_file, outdir):
    out_file = outdir/"urls.txt"
    if not subs_file.exists():
        console.log(f"[red]Subs file not found: {subs_file}[/red]")
        return out_file
    urls = set()
    for t in ["gau", "waybackurls"]:
        if shutil.which(t):
            console.log(f"[cyan]Running {t}...[/cyan]")
            res = run_cmd(f"cat {subs_file} | {t}")
            if res:
                urls.update(res.splitlines())
    if urls:
        out_file.write_text("\n".join(sorted(urls)))
        console.log(f"[green]URLs saved -> {out_file}[/green]")
    return out_file

def get_js(urls_file, outdir):
    js_file = outdir/"js-file.txt"
    if urls_file.exists():
        lines = urls_file.read_text().splitlines()
        js_urls = [l for l in lines if l.endswith(".js")]
        js_file.write_text("\n".join(js_urls))
        console.log(f"[green]JS files saved -> {js_file}[/green]")

def extract_php(urls_file, outdir):
    php_file = outdir/"php.txt"
    if urls_file.exists():
        lines = urls_file.read_text().splitlines()
        php_urls = [l for l in lines if ".php" in l]
        php_file.write_text("\n".join(php_urls))
        console.log(f"[green]PHP URLs saved -> {php_file}[/green]")

def extract_params(urls_file, outdir):
    params_file = outdir/"params.txt"
    if urls_file.exists():
        lines = urls_file.read_text().splitlines()
        all_params=[]
        for u in lines:
            try:
                q=parse_qs(urlparse(u).query)
                for k,v in q.items():
                    all_params.append(f"{u} | {k} | {','.join(v)}")
            except: continue
        params_file.write_text("\n".join(all_params))
        console.log(f"[green]Params saved -> {params_file}[/green]")

def gf_patterns(urls_file, outdir):
    patterns=["xss","sqli","lfi","rce","redirect"]
    if not shutil.which("gf") or not urls_file.exists(): return
    for pat in patterns:
        out = outdir/f"gf_{pat}.txt"
        run_cmd(f"cat {urls_file} | gf {pat} | sort -u > {out}")
        console.log(f"[green]GF {pat} -> {out}[/green]")

def extract_interest(subs_file, urls_file, outdir):
    interesting = ["login","rest","password","update","admin"]
    subs_out = outdir/"interest-subs.txt"
    urls_out = outdir/"interest-urls.txt"
    if subs_file.exists():
        lines = subs_file.read_text().splitlines()
        interest_subs = [l for l in lines if any(i in l for i in interesting)]
        subs_out.write_text("\n".join(interest_subs))
    if urls_file.exists():
        lines = urls_file.read_text().splitlines()
        interest_urls = [l for l in lines if any(i in l for i in interesting)]
        urls_out.write_text("\n".join(interest_urls))
    console.log(f"[green]Interest subs saved -> {subs_out}[/green]")
    console.log(f"[green]Interest URLs saved -> {urls_out}[/green]")

# ---- CLI ----
def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("-d","--domain",help="Single target")
    p.add_argument("-f","--file",help="Targets from file")
    p.add_argument("-all","--all",action="store_true",help="Run all steps")
    p.add_argument("-o","--out",default="results",help="Output dir")
    return p.parse_args()

# ---- Main ----
def main():
    args=parse_args()
    out_base=Path(args.out)
    targets=[]
    if args.domain: targets=[args.domain.strip()]
    elif args.file:
        path=Path(args.file)
        if not path.exists(): console.log(f"[red]File not found {path}[/red]"); return
        targets=[l.strip() for l in path.read_text().splitlines() if l.strip()]
    else: console.log("[red]Specify domain or file[/red]"); return

    install_tools()

    for t in targets:
        t_out=out_base/t
        t_out.mkdir(parents=True,exist_ok=True)
        console.log(Panel(f"Recon for {t}",title="Start"))

        # Step 1: Subs
        subs_file = get_subs(t, t_out)
        # Step 2: URLs
        urls_file = get_urls(subs_file, t_out)
        # Step 3: JS
        get_js(urls_file, t_out)
        # Step 4: PHP
        extract_php(urls_file, t_out)
        # Step 5: Params
        extract_params(urls_file, t_out)
        # Step 6: GF patterns
        gf_patterns(urls_file, t_out)
        # Step 7: Interesting URLs/Subs
        extract_interest(subs_file, urls_file, t_out)

        console.log(Panel(f"Done {t}",title="Finish"))

if __name__=="__main__":
    main()
