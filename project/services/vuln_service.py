"""
Vulnerability scanning service for the EASM application.
"""
import requests
import concurrent.futures
import nmap3
from config import NVD_gist_api_key
from services.tech_detection_service import integrate_tech_vulnerabilities, format_results

def check_vulnerabilities_alternative(domain):
    api_key = NVD_gist_api_key
    print(f"Scanning {domain} for technologies and vulnerabilities...")
    results = integrate_tech_vulnerabilities(domain, api_key)
    
    # Print technology scan results
    print(format_results(results))
    
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
            print(f"Error during scanning: {e}")
        if not result:
            print("No ports found, or there was an error in the nmap code.")
            vulnerabilities.append({"title": "Port Scan Error", 
                                   "description": "No open ports found, or there was an error in the nmap code.",
                                   "severity": "Unknown"})
        else:
            for ip_address, details in result.items():
                if not isinstance(details, dict) or 'ports' not in details:
                    continue
                    
                for port in details['ports']:
                    print(port)
                    if port['state'] == "open":
                        vulnerabilities.append({
                            'title': f'Open port {port["portid"]}',
                            'description': f'Port {port["portid"]} is open and might be vulnerable if not properly secured',
                            'severity': 'Medium' if port["portid"] not in [80, 443] else 'Info'
                        })
                    else:
                        continue

    # Run concurrent scans and wait for completion
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(check_headers, domain),
            executor.submit(check_open_ports, domain)
        ]
        concurrent.futures.wait(futures)

    # Add technology vulnerabilities to the list
    if results.get("status") == "success":
        for tech, vulns in results.get("vulnerabilities", {}).items():
            for vuln in vulns:
                vulnerabilities.append({
                    'title': f'Technology Vulnerability: {tech}',
                    'description': vuln.get("description", "No description available"),
                    'severity': vuln.get("severity", "Unknown"),
                    'cve_id': vuln.get("cve_id", "Unknown"),
                    'base_score': vuln.get("base_score", "N/A")
                })

    # Add technology information to the results
    if results.get("status") == "success":
        for tech in results.get("technologies", []):
            vulnerabilities.append({
                'title': f'Detected Technology: {tech["Name"]}',
                'description': f'Type: {tech["Type"]}, Version: {tech["Version"]}, Last Detected: {tech["Last_Detected"]}',
                'severity': 'Info'
            })

    return vulnerabilities