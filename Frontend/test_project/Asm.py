from flask import Flask, render_template, request, jsonify
import dns.resolver
import sqlite3
import csv
from datetime import datetime
import requests
import socket
import ssl
import concurrent.futures
import tldextract
from difflib import SequenceMatcher
from urllib.parse import urlparse
import os

app = Flask(__name__)

# Database setup
def setup_database():
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY,
                  domain TEXT,
                  scan_date TIMESTAMP,
                  dns_records TEXT,
                  ssl_info TEXT,
                  vulnerabilities TEXT,
                  subdomains TEXT,
                  shadow_domains TEXT)''')
    conn.commit()
    conn.close()

# DNS Records function
def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except Exception as e:
            records[record_type] = [f"Error: {str(e)}"]
    
    return records

# SSL Certificate function
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'expires': cert['notAfter']
                }
    except Exception as e:
        return {'error': str(e)}

# Vulnerability checking function
def check_vulnerabilities_alternative(domain):
    vulnerabilities = []
    
    def check_headers(domain):
        try:
            response = requests.get(f'https://{domain}', timeout=5, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS not set',
                'X-Content-Type-Options': 'No protection against MIME-type sniffing',
                'X-Frame-Options': 'No protection against clickjacking',
                'X-XSS-Protection': 'No XSS protection',
                'Content-Security-Policy': 'No CSP policy'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'title': f'Missing {header}',
                        'description': message,
                        'severity': 'Medium'
                    })
            
            server = headers.get('Server', '')
            if server:
                vulnerabilities.append({
                    'title': 'Server Version Disclosure',
                    'description': f'Server is revealing version information: {server}',
                    'severity': 'Low'
                })
                
        except requests.exceptions.SSLError:
            vulnerabilities.append({
                'title': 'SSL/TLS Issues',
                'description': 'SSL/TLS connection failed',
                'severity': 'High'
            })
        except Exception as e:
            vulnerabilities.append({
                'title': 'Connection Error',
                'description': str(e),
                'severity': 'Unknown'
            })

    def check_open_ports(domain):
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    vulnerabilities.append({
                        'title': f'Open Port: {port}',
                        'description': f'Port {port} is open and might be vulnerable if not properly secured',
                        'severity': 'Medium' if port not in [80, 443] else 'Info'
                    })
                sock.close()
            except:
                continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(check_headers, domain)
        executor.submit(check_open_ports, domain)

    return vulnerabilities

# Subdomain discovery function
def find_subdomains(domain):
    discovered_subdomains = set()
    
    def dns_bruteforce(domain, wordlist):
        try:
            resolver = dns.resolver.Resolver()
            try:
                answers = resolver.resolve(f"{wordlist}.{domain}", 'A')
                if answers:
                    discovered_subdomains.add(f"{wordlist}.{domain}")
            except:
                pass
        except Exception as e:
            pass

    def check_crt_sh(domain):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.ok:
                data = response.json()
                for entry in data:
                    name = entry['name_value'].lower()
                    for sub in name.split('\n'):
                        for subsub in sub.split(','):
                            if subsub.endswith(domain):
                                discovered_subdomains.add(subsub.strip())
        except Exception as e:
            print(f"Error in crt.sh: {e}")

    common_subdomains = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'portal'
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.submit(check_crt_sh, domain)
        bruteforce_futures = [
            executor.submit(dns_bruteforce, domain, subdomain)
            for subdomain in common_subdomains
        ]
        concurrent.futures.wait(bruteforce_futures)

    results = []
    for subdomain in sorted(discovered_subdomains):
        try:
            ip = socket.gethostbyname(subdomain)
            results.append({
                'subdomain': subdomain,
                'ip': ip,
                'status': 'Active'
            })
        except socket.gaierror:
            results.append({
                'subdomain': subdomain,
                'ip': 'N/A',
                'status': 'Inactive'
            })

    return results

# Shadow domain detection function
def find_shadow_domains(domain):
    shadow_domains = []
    ext = tldextract.extract(domain)
    domain_name = ext.domain
    tld = ext.suffix
    
    def generate_variations():
        variations = set()
        
        # Character swapping
        chars = list(domain_name)
        for i in range(len(chars)-1):
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variations.add(''.join(chars))
            chars[i], chars[i+1] = chars[i+1], chars[i]
        
        # Common TLD variations
        common_tlds = ['com', 'net', 'org', 'info']
        for variation in variations.copy():
            for new_tld in common_tlds:
                if new_tld != tld:
                    variations.add(f"{variation}.{new_tld}")
        
        return variations

    def check_domain_existence(domain_variation):
        try:
            answers = dns.resolver.resolve(domain_variation, 'A')
            ips = [str(rdata) for rdata in answers]
            
            similarity = SequenceMatcher(None, domain_name, 
                                      tldextract.extract(domain_variation).domain).ratio()
            
            return {
                'domain': domain_variation,
                'ips': ips,
                'similarity': round(similarity * 100, 2),
                'risk_level': 'High' if similarity > 0.8 else 'Medium' if similarity > 0.6 else 'Low'
            }
        except:
            return None

    variations = generate_variations()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain_existence, var): var 
                          for var in variations}
        
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            if result:
                shadow_domains.append(result)
    
    return sorted(shadow_domains, key=lambda x: x['similarity'], reverse=True)

# Export results to CSV
def export_to_csv(scan_results, domain):
    filename = f'scan_results_{domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Finding', 'Details'])
        
        # Write DNS records
        for record_type, records in scan_results['dns_info'].items():
            for record in records:
                writer.writerow(['DNS Record', record_type, record])
        
        # Write vulnerabilities
        for vuln in scan_results['vulnerabilities']:
            writer.writerow(['Vulnerability', vuln['title'], vuln['description']])
        
        # Write subdomains
        for sub in scan_results['subdomains']:
            writer.writerow(['Subdomain', sub['subdomain'], f"IP: {sub['ip']}, Status: {sub['status']}"])
        
        # Write shadow domains
        for shadow in scan_results['shadow_domains']:
            writer.writerow(['Shadow Domain', shadow['domain'], 
                           f"Similarity: {shadow['similarity']}%, Risk: {shadow['risk_level']}"])

    return filename

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_domain():
    domain = request.form['domain']
    
    # Perform all scans
    dns_info = get_dns_records(domain)
    ssl_info = get_ssl_info(domain)
    vulns = check_vulnerabilities_alternative(domain)
    subdomains = find_subdomains(domain)
    shadow_domains = find_shadow_domains(domain)
    
    # Store results in database
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    c.execute('''INSERT INTO scans 
                 (domain, scan_date, dns_records, ssl_info, vulnerabilities, subdomains, shadow_domains)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (domain, datetime.now(), str(dns_info), str(ssl_info), str(vulns), 
               str(subdomains), str(shadow_domains)))
    conn.commit()
    conn.close()
    
    # Export results
    scan_results = {
        'dns_info': dns_info,
        'ssl_info': ssl_info,
        'vulnerabilities': vulns,
        'subdomains': subdomains,
        'shadow_domains': shadow_domains
    }
    
    export_to_csv(scan_results, domain)
    
    return render_template('results.html',
                         domain=domain,
                         dns_info=dns_info,
                         ssl_info=ssl_info,
                         vulnerabilities=vulns,
                         subdomains=subdomains,
                         shadow_domains=shadow_domains)

if __name__ == '__main__':
    setup_database()
    app.run(debug=True, host='0.0.0.0', port=5000)