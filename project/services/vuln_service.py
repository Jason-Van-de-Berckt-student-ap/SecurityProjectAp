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
            print("Er zijn geen poorten gevonden, of er is een fout opgetreden.")
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(check_headers, domain)
        executor.submit(check_open_ports, domain)

    # Integrate technology vulnerability scanning
    vulnerabilities = integrate_tech_vulnerabilities(domain, vulnerabilities)

    return vulnerabilities