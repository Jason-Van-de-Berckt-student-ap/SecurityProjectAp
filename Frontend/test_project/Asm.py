from flask import Flask, render_template, request, jsonify
import dns.resolver
import sqlite3
import csv
import json
from datetime import datetime
import requests
import socket
import ssl
import concurrent.futures
import re
from urllib.parse import urlparse
import nmap3
import json

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
                  related_domains TEXT)''')
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
        # NOG NIET KLAAR --- KIJK IN LOOP-NMAPVOORPORTSCANNING VOOR VERDERE UITLEG WAAROM.
        nmap = nmap3.NmapScanTechniques()
        try:
            result = nmap.scan_top_ports(domain)
        except Exception as e:
            print(f"/nfout tijdens het scannen: {e}")
        if not result:
            print("Er zijn geen poorten gevonden, of er zit een fout in de nmap code.")
            vulnerabilities.append({"Error": "Geen open poorten gevonden, of er is een fout in de nmap code."})
        else:
            for ip_address, details in result.items():
                for port in details['ports']:
                    vulnerabilities.append({
                        'title': f'Open port {port["portid"]}',
                        'protocol': f'{port["protocol"]}',
                        'description': f'Port {port["portid"]} is open and might be vulnerable if not properly secured',
                        'severity': 'Medium' if port["portid"] not in [80, 443] else 'Info'
                    })

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
def find_related_domains(domain):
    """
    Find domains that are likely related to the target domain through various methods
    """
    related_domains = []
    
    def get_ssl_organization(domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    org_info = {}
                    for field in cert['subject']:
                        if field[0][0] == 'organizationName':
                            org_info['organization'] = field[0][1]
                        elif field[0][0] == 'organizationalUnitName':
                            org_info['unit'] = field[0][1]
                    return org_info
        except Exception as e:
            print(f"SSL Error: {str(e)}")
            return None

    def search_ct_logs_by_org(org_name):
        domains = set()
        try:
            url = f"https://crt.sh/?q={org_name}&output=json"
            response = requests.get(url, timeout=10)
            if response.ok:
                data = response.json()
                for entry in data:
                    name_value = entry['name_value'].lower()
                    # Filter out wildcards and non-domains
                    if '*' not in name_value and ' ' not in name_value:
                        domains.add(name_value)
        except Exception as e:
            print(f"CT Log Error: {str(e)}")
        return list(domains)

    def get_nameservers(domain):
        try:
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(domain, 'NS')
            return [str(ns) for ns in ns_records]
        except Exception as e:
            print(f"NS Error: {str(e)}")
            return []

    def get_spf_dmarc(domain):
        records = {}
        try:
            resolver = dns.resolver.Resolver()
            # Get SPF record
            txt_records = resolver.resolve(domain, 'TXT')
            for record in txt_records:
                record_text = str(record)
                if 'v=spf1' in record_text:
                    records['spf'] = record_text
            
            # Get DMARC record
            dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_records:
                record_text = str(record)
                if 'v=DMARC1' in record_text:
                    records['dmarc'] = record_text
        except Exception as e:
            print(f"SPF/DMARC Error: {str(e)}")
        return records

    def reverse_dns_lookup(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    # Process SSL organization information
    print(f"Checking SSL organization for {domain}")
    org_info = get_ssl_organization(domain)
    if org_info and 'organization' in org_info:
        print(f"Found organization: {org_info['organization']}")
        ct_domains = search_ct_logs_by_org(org_info['organization'])
        for domain_found in ct_domains:
            if domain_found != domain:
                related_domains.append({
                    'domain': domain_found,
                    'relation_type': 'Same Organization (SSL)',
                    'confidence': 'High',
                    'evidence': f"Organization: {org_info['organization']}"
                })

    # Check nameservers
    print("Checking nameservers")
    target_ns = get_nameservers(domain)
    if target_ns:
        related_domains.append({
            'domain': 'NS Information',
            'relation_type': 'Nameserver Pattern',
            'confidence': 'Medium',
            'evidence': f"Nameservers: {', '.join(target_ns)}"
        })

    # Check mail infrastructure
    print("Checking mail infrastructure")
    mail_records = get_spf_dmarc(domain)
    if mail_records:
        if 'spf' in mail_records:
            spf_includes = re.findall(r'include:([^\s]+)', mail_records['spf'])
            for included_domain in spf_includes:
                related_domains.append({
                    'domain': included_domain,
                    'relation_type': 'Mail Infrastructure',
                    'confidence': 'Medium',
                    'evidence': f"Included in SPF record"
                })

    # Check IP neighborhood
    print("Checking IP neighborhood")
    try:
        ip = socket.gethostbyname(domain)
        ip_parts = ip.split('.')
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        for i in range(1, 10):
            check_ip = f"{base_ip}.{i}"
            hostname = reverse_dns_lookup(check_ip)
            if hostname and hostname != domain:
                related_domains.append({
                    'domain': hostname,
                    'relation_type': 'Same IP Range',
                    'confidence': 'Medium',
                    'evidence': f"IP: {check_ip}"
                })
    except Exception as e:
        print(f"IP Range Error: {str(e)}")

    return sorted(related_domains, key=lambda x: {
        'High': 3,
        'Medium': 2,
        'Low': 1
    }[x['confidence']], reverse=True)

# Updated export_to_csv function
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
        
        # Write related domains
        for related in scan_results['related_domains']:
            writer.writerow(['Related Domain', related['domain'], 
                           f"Type: {related['relation_type']}, Confidence: {related['confidence']}, Evidence: {related['evidence']}"])

    return filename
@app.route('/')
def index():
    return render_template('index.html')

# Updated scan route
@app.route('/scan', methods=['POST'])
def scan_domain():
    domain = request.form['domain']
    scan_options = {
        'dns_scan': 'dns_scan' in request.form,
        'ssl_scan': 'ssl_scan' in request.form,
        'subdomain_scan': 'subdomain_scan' in request.form,
        'related_domains': 'related_domains' in request.form,
        'vuln_scan': 'vuln_scan' in request.form
    }
    
    # Initialize results dictionary
    results = {
        'dns_info': {},
        'ssl_info': {},
        'vulnerabilities': [],
        'subdomains': [],
        'related_domains': []
    }
    
    try:
        # Perform scans based on selected options
        if scan_options['dns_scan']:
            print(f"Starting DNS scan for {domain}")
            results['dns_info'] = get_dns_records(domain)
        
        if scan_options['ssl_scan']:
            print(f"Starting SSL scan for {domain}")
            results['ssl_info'] = get_ssl_info(domain)
        
        if scan_options['vuln_scan']:
            print(f"Starting vulnerability scan for {domain}")
            results['vulnerabilities'] = check_vulnerabilities_alternative(domain)
        
        if scan_options['subdomain_scan']:
            print(f"Starting subdomain discovery for {domain}")
            results['subdomains'] = find_subdomains(domain)
        
        if scan_options['related_domains']:
            print(f"Starting related domain discovery for {domain}")
            results['related_domains'] = find_related_domains(domain)
        
        # Store results in database
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scans 
                     (domain, scan_date, dns_records, ssl_info, vulnerabilities, 
                      subdomains, related_domains)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (domain, 
                   datetime.now(),
                   json.dumps(results['dns_info']),
                   json.dumps(results['ssl_info']),
                   json.dumps(results['vulnerabilities']),
                   json.dumps(results['subdomains']),
                   json.dumps(results['related_domains'])))
        conn.commit()
        conn.close()
        
        # Export results to CSV
        csv_file = export_to_csv(results, domain)
        
        # Render template with results
        return render_template('results.html',
                             domain=domain,
                             dns_info=results['dns_info'],
                             ssl_info=results['ssl_info'],
                             vulnerabilities=results['vulnerabilities'],
                             subdomains=results['subdomains'],
                             related_domains=results['related_domains'],
                             csv_file=csv_file)
                             
    except Exception as e:
        # Log the error
        print(f"Error during scan: {str(e)}")
        
        # Return error page or error message
        return render_template('results.html',
                             domain=domain,
                             error=str(e),
                             dns_info={},
                             ssl_info={'error': 'Scan failed'},
                             vulnerabilities=[],
                             subdomains=[],
                             related_domains=[])

# Updated export_to_csv function to handle new format
def export_to_csv(scan_results, domain):
    filename = f'scan_results_{domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Finding', 'Details'])
        
        # Write DNS records
        for record_type, records in scan_results['dns_info'].items():
            for record in records:
                writer.writerow(['DNS Record', record_type, record])
        
        # Write SSL info
        if not isinstance(scan_results['ssl_info'], dict) or 'error' not in scan_results['ssl_info']:
            for key, value in scan_results['ssl_info'].items():
                writer.writerow(['SSL Certificate', key, value])
        
        # Write vulnerabilities
        for vuln in scan_results['vulnerabilities']:
            writer.writerow(['Vulnerability', 
                           f"{vuln['title']} ({vuln['severity']})", 
                           vuln['description']])
        
        # Write subdomains
        for sub in scan_results['subdomains']:
            writer.writerow(['Subdomain', 
                           sub['subdomain'], 
                           f"IP: {sub['ip']}, Status: {sub['status']}"])
        
        # Write related domains
        for domain in scan_results['related_domains']:
            writer.writerow(['Related Domain',
                           f"{domain['domain']} ({domain['confidence']})",
                           f"Type: {domain['relation_type']}, Evidence: {domain['evidence']}"])

    return filename

if __name__ == '__main__':
    setup_database()
    app.run(debug=True, host='0.0.0.0', port=5000)