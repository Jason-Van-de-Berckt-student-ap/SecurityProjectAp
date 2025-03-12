from flask import Flask, render_template, request, jsonify
import dns.resolver
import sqlite3
import csv
import json
from datetime import datetime, timedelta
import requests
import socket
import ssl
import concurrent.futures
import tldextract
import re, time
from urllib.parse import urlparse
import os
from difflib import SequenceMatcher
from Frontend.test_project.config import BRAVE_API_KEY
import nmap3


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
def find_related_domains(domain, brave_api_key=None,  timeout=15, max_retries=2):
    related_domains = []
    base_domain = tldextract.extract(domain).domain
    found_domains = set()
    
    def query_crt_sh(query, attempt=0):
        """Helper function to query crt.sh with retries"""
        try:
            url = f"https://crt.sh/?q={query}&output=json"
            response = requests.get(url, timeout=timeout)
            
            if response.ok:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    print(f"Error decoding JSON from crt.sh for query: {query}")
                    return []
            else:
                print(f"crt.sh returned status code {response.status_code} for query: {query}")
                return []
                
        except requests.exceptions.Timeout:
            if attempt < max_retries:
                print(f"Timeout when querying crt.sh. Retrying ({attempt+1}/{max_retries})...")
                time.sleep(2)  # Wait before retrying
                return query_crt_sh(query, attempt + 1)
            else:
                print(f"Timeout when querying crt.sh after {max_retries} attempts.")
                return []
                
        except requests.exceptions.RequestException as e:
            print(f"Error querying crt.sh: {str(e)}")
            return []
        

    # Improved pattern matching for domain variations
    def generate_domain_patterns(domain):
        extracted = tldextract.extract(domain)
        base_domain = extracted.domain
        patterns = []
        
        # Basic variations
        patterns.extend([
            f"{base_domain}-",
            # f"{base_domain}_",
            # f"{base_domain}.",
            # f"{base_domain}dev",
            # f"{base_domain}test",
            # f"{base_domain}staging"
            # f"www.{base_domain}",
            # f"portal.{base_domain}",
            # f"my{base_domain}",
            # f"{base_domain} online",
            # f"{base_domain}-secure",
            # f"{base_domain} app",
            # f"{base_domain} api",
            # f"{base_domain} admin",
            # f"{base_domain} login",
            # f"{base_domain} mail",
            # f"{base_domain} webmail",
            # f"{base_domain} email",
            # f"{base_domain} ftp",
            # f"{base_domain} vpn",
            # f"{base_domain} wiki",
            # f"{base_domain} blog",
            # f"{base_domain} forum",
            # f"{base_domain} shop",
            # f"{base_domain} store",
            # f"{base_domain} support",
            # f"{base_domain} help",
            # f"{base_domain} contact"
        ])
        
        # Common corporate patterns
        if len(base_domain) > 1:  # Avoid too short names
            patterns.extend([
                f"{base_domain[:3]}",  # First 3 chars
                # f"{base_domain}-corp",
                # f"{base_domain}-inc",
                # f"{base_domain}-group"
            ])
        
        return patterns

    def validate_brave_api_key(api_key):
        if not api_key or len(api_key) < 30:  # Basic validation
            print("Invalid or missing Brave API key")
            return False
        return True

    def enhanced_brave_search(api_key, query, max_retries=3):
        if not validate_brave_api_key(api_key):
            return None
            
        url = "https://api.search.brave.com/res/v1/web/search"  # Remove the hardcoded query
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": api_key
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    params={
                        "q": query,
                        "count": 20,
                        "search_lang": "en"
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    print("Invalid Brave API key")
                    return None
                elif response.status_code == 429:
                    print(f"Rate limited. Response: {response.text}")
                    wait_time = int(response.headers.get('Retry-After', 60))
                    print(f"Rate limited. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"Brave API error: {response.status_code}, {response.text}")
                    
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                continue
                
        return None

    def find_domains_in_ssl_cert(domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    domains = set()
                    
                    # Check Subject Alternative Names
                    for type_, san in cert.get('subjectAltName', []):
                        if type_ == 'DNS':
                            domains.add(san.lower())
                            
                    return list(domains)
        except Exception as e:
            print(f"SSL cert check failed: {str(e)}")
            return []

    def analyze_dns_txt_records(domain):
        found_domains = set()
        try:
            resolver = dns.resolver.Resolver()
            txt_records = resolver.resolve(domain, 'TXT')
            
            for record in txt_records:
                record_text = str(record)
                # Look for domains in SPF records
                if 'v=spf1' in record_text:
                    domains = re.findall(r'include:([^\s]+)', record_text)
                    found_domains.update(domains)
                    
                # Look for domains in DMARC records
                if 'v=DMARC1' in record_text:
                    domains = re.findall(r'rua=mailto:([^@]+@[^\s;]+)', record_text)
                    found_domains.update([d.split('@')[1] for d in domains])
                    
        except Exception as e:
            print(f"DNS TXT record analysis failed: {str(e)}")
            
        return list(found_domains)

    # Main execution flow
    try:
        # 1. Generate domain patterns
        patterns = generate_domain_patterns(domain)

        # 2. Check SSL certificate for related domains
        ssl_domains = find_domains_in_ssl_cert(domain)
        for ssl_domain in ssl_domains:
            if ssl_domain != domain:
                related_domains.append({
                    'domain': ssl_domain,
                    'relation_type': 'SSL Certificate',
                    'confidence': 'High',
                    'evidence': 'Found in SSL certificate SAN'
                })
        
        # 3. Analyze DNS TXT records
        txt_domains = analyze_dns_txt_records(domain)
        for txt_domain in txt_domains:
            related_domains.append({
                'domain': txt_domain,
                'relation_type': 'DNS TXT Record',
                'confidence': 'Medium',
                'evidence': 'Found in SPF/DMARC records'
            })
        
        # 4. Use Brave Search if API key is provided
        if brave_api_key:
            # Try a direct search for the domain name (not using site: operator)
            for pattern in patterns:
                print(f"Searching for domain name: {pattern}")
                results = enhanced_brave_search(brave_api_key, f'"{domain}"')
                time.sleep(1.5)  # Respect rate limits
                if results and 'web' in results and 'results' in results['web']:
                    for result in results['web']['results']:
                        url = result.get('url', '')
                        title = result.get('title', '')
                        description = result.get('description', '')
                        
                        if url:
                            parsed = urlparse(url)
                            found_domain = parsed.netloc.lower()
                            if found_domain.startswith('www.'):
                                found_domain = found_domain[4:]
                                
                            # Don't add the domain itself
                            if found_domain != domain and found_domain not in [d['domain'] for d in related_domains]:
                                # Check if this looks like a related domain
                                extracted = tldextract.extract(found_domain)
                                if extracted.domain and (
                                    extracted.domain.startswith(domain[:3]) or
                                    domain[:3] in extracted.domain or
                                    SequenceMatcher(None, extracted.domain, tldextract.extract(domain).domain).ratio() > 0.6
                                ):
                                    related_domains.append({
                                        'domain': found_domain,
                                        'relation_type': 'Search Result',
                                        'confidence': 'Low',
                                        'evidence': f'Found in Brave search results for "{domain}"'
                                    })
        # 5. Query Certificate Transparency logs
        print(f"Searching Certificate Transparency logs for {domain}")
        wildcard_results = query_crt_sh(f"%.{domain}")
    
        for entry in wildcard_results:
            name = entry.get('name_value', '').lower()
            # Split on both newlines and commas
            for domain_part in re.split(r'[\n,]', name):
                domain_part = domain_part.strip()
                if domain_part and '*' not in domain_part:
                    found_domains.add(domain_part)

        if not found_domains:
            print("No results from wildcard search, trying base domain...")
            base_results = query_crt_sh(base_domain)
        
            for entry in base_results:
                name = entry.get('name_value', '').lower()
                for domain_part in re.split(r'[\n,]', name):
                    domain_part = domain_part.strip()
                    if domain_part and '*' not in domain_part:
                        # Check if this is a potential related domain
                        extracted = tldextract.extract(domain_part)
                        if extracted.domain and domain_part.endswith(f".{domain}"):
                            found_domains.add(domain_part)
                        # Also look for potential shadow domains
                        elif extracted.domain and base_domain != extracted.domain and (
                            extracted.domain.startswith(base_domain[:3]) or
                            extracted.domain.endswith(base_domain[-3:]) or
                            SequenceMatcher(None, extracted.domain, base_domain).ratio() > 0.6
                        ):
                            found_domains.add(domain_part)
    
        if not found_domains:
            print("No results from crt.sh, trying alternative sources...")
            try:
                # Query certspotter.com API (another free CT log source)
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                response = requests.get(url, timeout=10)
                
                if response.ok:
                    data = response.json()
                    for cert in data:
                        dns_names = cert.get('dns_names', [])
                        for dns_name in dns_names:
                            if dns_name and dns_name != domain:
                                found_domains.add(dns_name.lower())
            except Exception as e:
                print(f"Error using alternative CT log source: {str(e)}")
        
        # Process found domains from CT logs
        for found_domain in found_domains:
            if found_domain != domain:
                # Determine confidence based on relationship
                if found_domain.endswith(f".{domain}"):
                    found_domains.remove(found_domain)
                else:
                    similarity = SequenceMatcher(None, 
                                tldextract.extract(found_domain).domain, 
                                base_domain).ratio()
                    if similarity > 0.8:
                        confidence = "Medium"
                        relation = "Similar Domain"
                    else:
                        confidence = "Low"
                        relation = "Potentially Related Domain"
                
                related_domains.append({
                    'domain': found_domain,
                    'relation_type': relation,
                    'confidence': confidence,
                    'evidence': 'Found in Certificate Transparency logs'
                })

        # 6. Remove duplicates while preserving highest confidence
        seen_domains = {}
        confidence_scores = {'High': 3, 'Medium': 2, 'Low': 1}
        
        for item in related_domains:
            domain_key = item['domain']
            if (domain_key not in seen_domains or 
                confidence_scores[item['confidence']] > 
                confidence_scores[seen_domains[domain_key]['confidence']]):
                seen_domains[domain_key] = item
        
        return sorted(
            list(seen_domains.values()),
            key=lambda x: confidence_scores[x['confidence']],
            reverse=True
        )
        
    except Exception as e:
        print(f"Error in find_related_domains: {str(e)}")
        return []

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
            results['related_domains'] = find_related_domains(domain, BRAVE_API_KEY)
        
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