# """
# Vulnerability scanning service for the EASM application.
# """
# import requests
# import concurrent.futures
# import nmap3

# def check_vulnerabilities_alternative(domain):
#     """
#     Check for common vulnerabilities in a domain.
    
#     Args:
#         domain: Domain name to scan
        
#     Returns:
#         list: List of vulnerability dictionaries
#     """
#     vulnerabilities = []
    
#     def check_headers(domain):
#         try:
#             response = requests.get(f'https://{domain}', timeout=5, verify=False)
#             headers = response.headers
            
#             security_headers = {
#                 'Strict-Transport-Security': 'HSTS not set',
#                 'X-Content-Type-Options': 'No protection against MIME-type sniffing',
#                 'X-Frame-Options': 'No protection against clickjacking',
#                 'X-XSS-Protection': 'No XSS protection',
#                 'Content-Security-Policy': 'No CSP policy'
#             }
            
#             for header, message in security_headers.items():
#                 if header not in headers:
#                     vulnerabilities.append({
#                         'title': f'Missing {header}',
#                         'description': message,
#                         'severity': 'Medium'
#                     })
            
#             server = headers.get('Server', '')
#             if server:
#                 vulnerabilities.append({
#                     'title': 'Server Version Disclosure',
#                     'description': f'Server is revealing version information: {server}',
#                     'severity': 'Low'
#                 })
                
#         except requests.exceptions.SSLError:
#             vulnerabilities.append({
#                 'title': 'SSL/TLS Issues',
#                 'description': 'SSL/TLS connection failed',
#                 'severity': 'High'
#             })
#         except Exception as e:
#             vulnerabilities.append({
#                 'title': 'Connection Error',
#                 'description': str(e),
#                 'severity': 'Unknown'
#             })

#     def check_open_ports(domain):
#         nmap = nmap3.NmapScanTechniques()
#         try:
#             result = nmap.scan_top_ports(domain)
#         except Exception as e:
#             print(f"/nfout tijdens het scannen: {e}")
#         if not result:
#             print("Er zijn geen poorten gevonden, of er zit een fout in de nmap code.")
#             vulnerabilities.append({"Error": "Geen open poorten gevonden, of er is een fout in de nmap code."})
#         else:
#             for ip_address, details in result.items():
#                 for port in details['ports']:
#                     vulnerabilities.append({
#                         'title': f'Open port {port["portid"]}',
#                         'protocol': f'{port["protocol"]}',
#                         'description': f'Port {port["portid"]} is open and might be vulnerable if not properly secured',
#                         'severity': 'Medium' if port["portid"] not in [80, 443] else 'Info'
#                     })

#     with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
#         executor.submit(check_headers, domain)
#         executor.submit(check_open_ports, domain)

#     return vulnerabilities


import requests
from bs4 import BeautifulSoup
import json
import re

def extract_version(text):
    # Verbeterde regex voor versieherkenning (ondersteunt semver, datums, en complexe versies)
    version_match = re.search(r'(v?[\d\.]+(-\w+)?(\.\d+)*)|(\d{4}-\d{2}-\d{2})', text)
    return version_match.group(0) if version_match else "Version unknown"

def get_website_technologies(url):
    technologies = {
        "web_frameworks": {},
        "web_servers": [],
        "versions": {},
        "services": {},
        "operating_system": ""
    }

    try:
        response = requests.get(url)
        response.raise_for_status()

        # Headers analyseren
        headers = response.headers
        if 'Server' in headers:
            server_header = headers['Server']
            technologies["web_servers"].append(server_header)
            technologies["operating_system"] = (
                "Linux" if 'Linux' in server_header else
                "Windows" if 'Windows' in server_header else
                "macOS" if 'Darwin' in server_header else "Unknown"
            )

        # Versie-informatie uit headers halen
        version_headers = ['X-Powered-By', 'X-Generator', 'X-Content-Type']
        for header in version_headers:
            if header in headers:
                technologies["versions"][header] = extract_version(headers[header])

        # HTML analyseren
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Web Frameworks detecteren met versies
        framework_patterns = {
            r'([\w/-]+)\.react(-dom)?(\.min)?\.js': 'React',
            r'vue(@[\d\.]+)?(\.min)?\.js': 'Vue.js',
            r'angular[^/]*\.js': 'Angular',
            r'jquery([-.])(\d+\.\d+\.\d+)': 'jQuery',
            r'bootstrap(/js/)?([\d\.]+)/': 'Bootstrap',
            r'ember(.prod)?\.js': 'Ember.js'
        }

        for script in soup.find_all('script'):
            src = script.get('src', '')
            content = str(script)
            
            for pattern, framework in framework_patterns.items():
                if re.search(pattern, src, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                    version = extract_version(src) if src else extract_version(content)
                    technologies["web_frameworks"][framework] = version

        # Populaire Services detecteren
        service_patterns = {
            # Analytics
            r'google-analytics\.com/analytics\.js': ('Google Analytics', 'src'),
            r'googletagmanager\.com/gtm\.js': ('Google Tag Manager', 'src'),
            # Social Media
            r'connect\.facebook\.net/[a-z]/sdk\.js': ('Facebook SDK', 'src'),
            r'platform\.twitter\.com/widgets\.js': ('Twitter SDK', 'src'),
            # Payment
            r'js\.stripe\.com/v3': ('Stripe', 'src'),
            r'www\.paypalobjects\.com/api/checkout\.js': ('PayPal', 'src'),
            # CMS
            r'/wp-content/': ('WordPress', 'content'),
            r'cdn\.shopify\.com/s/': ('Shopify', 'src'),
            # Hosting
            r'cloudflare\.com/ajax/libs/': ('Cloudflare', 'src'),
            # Marketing
            r'hs-scripts\.com': ('HubSpot', 'src'),
            r'piwik\.js': ('Matomo', 'src')
        }

        for pattern, (service, loc) in service_patterns.items():
            if loc == 'src':
                for script in soup.find_all('script', src=re.compile(pattern)):
                    technologies["services"][service] = extract_version(script['src'])
            else:
                if re.search(pattern, response.text, re.IGNORECASE):
                    technologies["services"][service] = "Detected"

        # Specifieke meta-tags checken
        meta_checks = {
            'generator': ['WordPress', 'Drupal', 'Joomla'],
            'framework': ['React', 'Vue.js', 'Angular']
        }

        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            
            if name == 'generator':
                for cms in meta_checks['generator']:
                    if cms in content:
                        technologies["web_frameworks"][cms] = extract_version(content)
            
            if name == 'framework':
                for framework in meta_checks['framework']:
                    if framework in content:
                        technologies["web_frameworks"][framework] = extract_version(content)

    except requests.RequestException as e:
        print(f"Fout: {e}")

    return technologies

def save_to_json(data, filename='technologies.json'):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    url = input("Voer URL in: ")
    data = get_website_technologies(url)
    save_to_json(data)
    print("Data opgeslagen.")