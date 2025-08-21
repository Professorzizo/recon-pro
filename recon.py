#!/usr/bin/env python3
import argparse, asyncio, subprocess, shutil, os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()

# ---- utilities ----
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

# ---- collectors ----
def get_subs(domain, outdir):
    out_file = outdir/"subs.txt"
    for t in ["subfinder", "assetfinder"]:
        if shutil.which(t):
            console.log(f"[cyan]Running {t}...[/cyan]")
            res = run_cmd(f"{t} -d {domain} -silent")
            if res:
                with open(out_file,"a") as f: f.write(res+"\n")
    console.log(f"[green]Subs saved -> {out_file}[/green]")
    return out_file

def get_urls(domain, outdir):
    out_file = outdir/"urls.txt"
    for t in ["gau", "waybackurls"]:
        if shutil.which(t):
            console.log(f"[cyan]Running {t}...[/cyan]")
            res = run_cmd(f"{t} {domain}")
            if res:
                with open(out_file,"a") as f: f.write(res+"\n")
    console.log(f"[green]URLs saved -> {out_file}[/green]")
    return out_file

def get_js(urls_file, outdir):
    js_file = outdir/"js-file.txt"
    if urls_file.exists():
        with open(urls_file) as f:
            lines = f.read().splitlines()
        js_urls = [l for l in lines if l.endswith(".js")]
        js_file.write_text("\n".join(js_urls))
    console.log(f"[green]JS files saved -> {js_file}[/green]")

def extract_php(urls_file, outdir):
    php_file = outdir/"php.txt"
    if urls_file.exists():
        with open(urls_file) as f:
            lines = f.read().splitlines()
        php_urls = [l for l in lines if ".php" in l]
        php_file.write_text("\n".join(php_urls))
    console.log(f"[green]PHP URLs saved -> {php_file}[/green]")

def extract_params(urls_file, outdir):
    from urllib.parse import urlparse, parse_qs
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
    if not shutil.which("gf"): return
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
    p.add_argument("-s","--subs",action="store_true",help="Get subs")
    p.add_argument("-u","--urls",action="store_true",help="Get URLs")
    p.add_argument("-j","--js",action="store_true",help="Get JS")
    p.add_argument("-p","--params",action="store_true",help="Get params")
    p.add_argument("--php",action="store_true",help="Get PHP URLs")
    p.add_argument("-g","--gf",action="store_true",help="Run GF patterns")
    p.add_argument("--interest",action="store_true",help="Extract interesting URLs/Subs")
    p.add_argument("-all","--all",action="store_true",help="Run all steps")
    p.add_argument("-o","--out",default="results",help="Output dir")
    return p.parse_args()

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

        subs_file = t_out/"subs.txt"
        urls_file = t_out/"urls.txt"

        if args.subs or args.all: get_subs(t,t_out)
        if args.urls or args.all: get_urls(t,t_out)
        if args.js or args.all: get_js(urls_file,t_out)
        if args.php or args.all: extract_php(urls_file,t_out)
        if args.params or args.all: extract_params(urls_file,t_out)
        if args.gf or args.all: gf_patterns(urls_file,t_out)
        if args.interest or args.all: extract_interest(subs_file,urls_file,t_out)

        console.log(Panel(f"Done {t}",title="Finish"))

if __name__=="__main__":
    main()
