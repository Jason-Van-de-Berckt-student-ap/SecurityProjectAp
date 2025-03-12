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


# import requests
# from bs4 import BeautifulSoup
# import re
# from jinja2 import Environment, FileSystemLoader

# # Vulnerability database
# VULNERABILITY_DB = {
#     "jQuery": {
#         "min_version": "3.6.0",
#         "severity": "High",
#         "description": "Outdated jQuery version found. Vulnerable to XSS attacks."
#     },
#     "WordPress": {
#         "min_version": "6.4.3", 
#         "severity": "High",
#         "description": "Outdated WordPress version. Security updates required."
#     },
#     "React": {
#         "min_version": "18.2.0",
#         "severity": "Medium",
#         "description": "Older React version. Potential performance issues."
#     }
# }

# def extract_version(text):
#     version_match = re.search(
#         r'(v?\d+\.\d+\.\d+(-\w+)?)|(\d{4}-\d{2}-\d{2})|(\d+\.\d+(\.\d+)*)',
#         text
#     )
#     return version_match.group(0) if version_match else "unknown"

# def analyze_vulnerabilities(tech_data):
#     vulnerabilities = []
#     print(tech_data)
    
#     # Check web frameworks
#     for framework, version in tech_data["web_frameworks"].items():
#         if framework in VULNERABILITY_DB:
#             db_entry = VULNERABILITY_DB[framework]
#             if version < db_entry["min_version"]:
#                 vulnerabilities.append({
#                     "title": f"Outdated {framework} Version",
#                     "description": f"{db_entry['description']} Detected: {version}, Required: {db_entry['min_version']}+",
#                     "severity": db_entry["severity"]
#                 })
#             else:
#                 vulnerabilities.append({
#                     "title": f"Framework: {framework} {version}",
#                     "description": "Unknown web framework versie detected and not in the database",
#                     "severity": "Low"
#                 })
#         else:
#             vulnerabilities.append({
#                 "title": f"Unindexed Framework: {framework} {version}",
#                 "description": "Unknown web framework detected",
#                 "severity": "Low"
#             })
    
#     # Check services
#     for service, version in tech_data["services"].items():
#         if "Shopify" in service and version == "Detected":
#             vulnerabilities.append({
#                 "title": "Shopify Detected",
#                 "description": "E-commerce platform requires regular security audits",
#                 "severity": "Medium"
#             })
    
#     return vulnerabilities
    
# def get_website_technologies(domain):
#     technologies = {
#         "web_frameworks": {},
#         "web_servers": [],
#         "versions": {},
#         "services": {},
#         "operating_system": ""
#     }
#     domain = domain.strip("https://").strip("http://").strip("wwww.")

#     try:
#         response = requests.get(f'https://www.{domain}', timeout=5, verify=False)
#         response.raise_for_status()

#         headers = response.headers
#         server_header = headers.get('Server', '')
#         if server_header:
#             technologies["web_servers"].append(server_header)
#             technologies["operating_system"] = (
#                 "Linux" if 'Linux' in server_header else
#                 "Windows" if 'Windows' in server_header else
#                 "macOS" if 'Darwin' in server_header else "Unknown"
#             )

#         for header in ['X-Powered-By', 'X-Generator']:
#             if header in headers:
#                 technologies["versions"][header] = extract_version(headers[header])

#         soup = BeautifulSoup(response.text, 'html.parser')
        
#         framework_patterns = {
#             r'([\w/-]+)\.react(-dom)?(\.min)?\.js': 'React',
#             r'vue(@[\d\.]+)?(\.min)?\.js': 'Vue.js',
#             r'angular[^/]*\.js': 'Angular',
#             r'jquery-(\d+\.\d+\.\d+)': 'jQuery',
#             r'bootstrap/dist/js/bootstrap\.(min\.)?js': 'Bootstrap',
#             r'next/dist/': 'Next.js'
#         }

#         for script in soup.find_all(['script', 'link']):
#             src = script.get('src', '') or script.get('href', '')
#             for pattern, framework in framework_patterns.items():
#                 if re.search(pattern, src, re.IGNORECASE):
#                     technologies["web_frameworks"][framework] = extract_version(src)

#         service_patterns = {
#             r'googletagmanager\.com/gtm\.js': ('Google Tag Manager', 'src'),
#             r'hotjar\.com/h.js': ('Hotjar', 'src'),
#             r'js\.stripe\.com/v3': ('Stripe', 'src'),
#             r'checkout\.razorpay.com': ('Razorpay', 'src'),
#             r'/wp-content/': ('WordPress', 'content'),
#             r'cdn.shopify.com/s/': ('Shopify', 'src')
#         }

#         for pattern, (service, loc) in service_patterns.items():
#             if loc == 'src':
#                 for script in soup.find_all('script', src=re.compile(pattern)):
#                     technologies["services"][service] = extract_version(script['src'])
#             else:
#                 if re.search(pattern, response.text, re.IGNORECASE):
#                     technologies["services"][service] = "Detected"

#         for meta in soup.find_all('meta'):
#             name = meta.get('name', '').lower()
#             content = meta.get('content', '')
            
#             if name == 'generator':
#                 if 'WordPress' in content:
#                     version = re.search(r'WordPress (\d+\.\d+\.\d+)', content)
#                     technologies["web_frameworks"]["WordPress"] = version.group(1) if version else "Detected"
                
#                 if 'Shopify' in content:
#                     technologies["services"]["Shopify"] = "Detected"

#     except Exception as e:
#         print(f"Scan error: {str(e)}")

#     return technologies

# def check_vulnerabilities_alternative(domain):
#     try:
#         tech_data = get_website_technologies(domain)
#         vulnerabilities = analyze_vulnerabilities(tech_data)
#         return vulnerabilities
#         print(vulnerabilities)
            
#     except Exception as e:
#         print(f"Error generating report: {str(e)}")
"""
Vulnerability scanning service for the EASM application.
"""
"""
Vulnerability scanning service for the EASM application.
"""
import requests
import concurrent.futures
import nmap3
from services.tech_detection_service import integrate_tech_vulnerabilities

def check_vulnerabilities_alternative(domain):
    """
    Check for common vulnerabilities in a domain.
    
    Args:
        domain: Domain name to scan
        
    Returns:
        list: List of vulnerability dictionaries
    """
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
        nmap = nmap3.NmapScanTechniques()
        try:
            result = nmap.scan_top_ports(domain)
        except Exception as e:
            print(f"/nfout tijdens het scannen: {e}")
        if not result:
            print("Er zijn geen poorten gevonden, of er zit een fout in de nmap code.")
            vulnerabilities.append({"title": "Port Scan Error", 
                                   "description": "No open ports found, or there was an error in the nmap code.",
                                   "severity": "Unknown"})
        else:
            for ip_address, details in result.items():
                if not isinstance(details, dict) or 'ports' not in details:
                    continue
                    
                for port in details['ports']:
                    vulnerabilities.append({
                        'title': f'Open port {port["portid"]}',
                        'description': f'Port {port["portid"]} is open and might be vulnerable if not properly secured',
                        'severity': 'Medium' if port["portid"] not in [80, 443] else 'Info'
                    })

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(check_headers, domain)
        executor.submit(check_open_ports, domain)

    # Integrate technology vulnerability scanning
    vulnerabilities = integrate_tech_vulnerabilities(domain, vulnerabilities)

    return vulnerabilities