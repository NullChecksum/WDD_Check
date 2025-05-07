import subprocess
import socket
import re
import whois
import os
from colorama import init, Fore, Back, Style
from tabulate import tabulate

init(autoreset=True)

# ---------- Utility Functions ----------

def run_dig_command(domain, record_type):
    try:
        result = subprocess.run(['dig', '+short', domain, record_type], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return ""

def resolve_ip(hostname):
    try:
        ipv4 = socket.gethostbyname(hostname)
    except:
        ipv4 = "-"
    try:
        ipv6_list = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        ipv6 = list(set([ip[-1][0] for ip in ipv6_list]))[0]
    except:
        ipv6 = "-"
    return ipv4, ipv6

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "-"

# ---------- WHOIS & DNS ----------

def get_whois_and_resolution(domain):
    try:
        w = whois.whois(domain)
        ipv4 = run_dig_command(domain, 'A').splitlines()[0] if run_dig_command(domain, 'A') else "-"
        ipv6 = run_dig_command(domain, 'AAAA').splitlines()[0] if run_dig_command(domain, 'AAAA') else "-"
        ptr = reverse_dns(ipv4) if ipv4 != "-" else "-"
        cname = run_dig_command(domain, 'CNAME')
        return {
            "Domain": domain,
            "IPv4": ipv4,
            "IPv6": ipv6,
            "PTR (reverse)": ptr,
            "CNAME": cname if cname else "-",
            "Registrar": w.registrar or "-",
            "Registrant Name": w.name or "-",
            "Organization": w.org or "-",
            "Email": w.emails[0] if isinstance(w.emails, list) else w.emails or "-",
            "Phone": w.phone or "-",
            "Address": ', '.join(filter(None, [w.address, w.city, w.state, w.zipcode, w.country])) if hasattr(w, 'address') else "-",
            "Created": str(w.creation_date) if w.creation_date else "-",
            "Expiry": str(w.expiration_date) if w.expiration_date else "-"
        }
    except Exception:
        return {
            "Domain": domain,
            "IPv4": "-", "IPv6": "-", "PTR (reverse)": "-", "CNAME": "-",
            "Registrar": "-", "Registrant Name": "-", "Organization": "-",
            "Email": "-", "Phone": "-", "Address": "-",
            "Created": "-", "Expiry": "-"
        }

def get_all_dns_records(domain):
    return {
        "A": run_dig_command(domain, 'A'),
        "AAAA": run_dig_command(domain, 'AAAA'),
        "MX": run_dig_command(domain, 'MX'),
        "NS": run_dig_command(domain, 'NS'),
        "TXT": run_dig_command(domain, 'TXT'),
        "CNAME": run_dig_command(domain, 'CNAME')
    }

def get_mx_ips(domain):
    mx_raw = run_dig_command(domain, 'MX')
    mx_records = []
    for line in mx_raw.splitlines():
        match = re.search(r'(\S+)$', line)
        if match:
            host = match.group(1).strip('.')
            ipv4, ipv6 = resolve_ip(host)
            mx_records.append((host, ipv4, ipv6))
    return mx_records

# ---------- Email Authentication ----------

def extract_selectors_from_spf(spf_record):
    selectors = []
    if spf_record:
        includes = re.findall(r'include:(\S+)', spf_record)
        for domain in includes:
            parts = domain.split('.')
            if len(parts) > 2:
                selectors.append(parts[0])
    return selectors

def check_dkim_record(domain, selector):
    dkim_domain = f"{selector}._domainkey.{domain}"
    return run_dig_command(dkim_domain, 'TXT')

def check_spf(domain):
    txt = run_dig_command(domain, 'TXT')
    return next((r for r in txt.split('\n') if 'v=spf1' in r), None)

def check_dmarc(domain):
    return run_dig_command(f'_dmarc.{domain}', 'TXT')

def check_dkim(domain, spf_record):
    selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mailjet']
    if spf_record:
        selectors = list(set(selectors + extract_selectors_from_spf(spf_record)))
    results = []
    for selector in selectors:
        record = check_dkim_record(domain, selector)
        if record:
            results.append((selector, record))
    return results

# ---------- Output Formatting ----------

def print_header(text):
    print(f"\n{Fore.CYAN}{Back.BLACK}{Style.BRIGHT} {text} {Style.RESET_ALL}")

def print_subheader(text):
    print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")

def print_info(text):
    print(f"{Fore.WHITE}{text}{Style.RESET_ALL}")

# ---------- Main Logic ----------

def analyze_domain(domain):
    print_header(f"Domain Analysis: {domain}")

    whois_data = get_whois_and_resolution(domain)
    print_header("WHOIS & Resolution")
    for k, v in whois_data.items():
        print_subheader(k)
        print_info(v)

    print_header("DNS Records Overview")
    records = get_all_dns_records(domain)
    for rtype, data in records.items():
        print_subheader(f"{rtype} Records")
        print_info(data if data else "No data")

    print_header("Mail Server IPs")
    mx_data = get_mx_ips(domain)
    if mx_data:
        print(tabulate(mx_data, headers=["MX Host", "IPv4", "IPv6"], tablefmt="fancy_grid"))
    else:
        print_info("No MX records found.")

    spf_record = check_spf(domain)
    dkim_results = check_dkim(domain, spf_record)
    dmarc_record = check_dmarc(domain)

    print_header("Email Authentication Summary")
    summary = [
        ["SPF", Fore.GREEN + "✓ Present" + Style.RESET_ALL if spf_record else Fore.RED + "✗ Missing" + Style.RESET_ALL],
        ["DKIM", Fore.GREEN + "✓ Present" + Style.RESET_ALL if dkim_results else Fore.RED + "✗ Missing" + Style.RESET_ALL],
        ["DMARC", Fore.GREEN + "✓ Present" + Style.RESET_ALL if dmarc_record else Fore.RED + "✗ Missing" + Style.RESET_ALL]
    ]
    print(tabulate(summary, headers=["Record", "Status"], tablefmt="fancy_grid"))

    if spf_record:
        print_header("SPF Record")
        print_info(spf_record)

    if dkim_results:
        print_header("DKIM Records")
        for sel, rec in dkim_results:
            print_subheader(f"Selector: {sel}")
            print_info(rec)
    else:
        print_info("No DKIM records found.")

    if dmarc_record:
        print_header("DMARC Record")
        print_info(dmarc_record)
    else:
        print_info("No DMARC record found.")

# ---------- Execution ----------

if __name__ == "__main__":
    print_header("Domain Analyzer")
    choice = input("Analyze single domain or from list? (s = single, l = list): ").lower()

    if choice == "s":
        domain = input("Enter domain to analyze: ").strip()
        if domain:
            analyze_domain(domain)
        else:
            print("No domain entered.")

    elif choice == "l":
        filename = input("Enter filename with domain list (e.g. domains.txt): ").strip()
        if os.path.exists(filename):
            with open(filename, "r") as f:
                domains = [line.strip() for line in f if line.strip()]
            for d in domains:
                analyze_domain(d)
        else:
            print(f"File '{filename}' not found.")
    else:
        print("Invalid selection.")
