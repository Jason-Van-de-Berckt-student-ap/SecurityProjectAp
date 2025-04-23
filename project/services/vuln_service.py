"""
Vulnerability scanning service for the EASM application.
"""
import requests
import concurrent.futures
import nmap3
from config import NVD_gist_api_key
from services.tech_detection_service import integrate_tech_vulnerabilities, format_results, scan_website_technologies

def check_vulnerabilities_alternative(domain):
    """
    Check for common vulnerabilities in a domain.
    
    Args:
        domain: Domain name to scan
        
    Returns:
        list: List of vulnerability dictionaries
    """
    api_key = NVD_gist_api_key
    print(f"Scanning {domain} for technologies and vulnerabilities...")
    
    # Initialize vulnerabilities list
    vulnerabilities = []
    
    # First, scan for technologies
    tech_results = integrate_tech_vulnerabilities(domain, api_key)
    print(format_results(tech_results))
    
    # Add technology information to vulnerabilities
    if tech_results.get("status") == "success":
        # Add detected technologies
        for tech, vulns in tech_results.get("vulnerabilities", {}).items():
            if not vulns:
                continue
            try:
                vulns.sort(key=lambda x: float(x.get("base_score")) if x.get("base_score") != "N/A" else 0, reverse=True)
            except Exception as e:
                print(f"Error sorting vulnerabilities: {e}")
            for vuln in vulns:
                if vuln.get("cve_id") != "VERSION_UNKNOWN":
                    vuln["description"] = ""
                else:
                    continue
                vulnerabilities.append({
                    'title': f'Technology Vulnerability: {tech}',
                    'description': vuln.get("description", "No description available"),
                    'severity': vuln.get("severity", "Unknown"),
                    'cve_id': vuln.get("cve_id", "Unknown"),
                    'base_score': vuln.get("base_score", "N/A"),
                    'type': 'tech_vulnerability'
                })
        
        # Add technology vulnerabilities

    
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
                        'severity': 'Medium',
                        'type': 'security_header'
                    })
            
            server = headers.get('Server', '')
            if server:
                vulnerabilities.append({
                    'title': 'Server Version Disclosure',
                    'description': f'Server is revealing version information: {server}',
                    'severity': 'Low',
                    'type': 'server_info'
                })
                
        except requests.exceptions.SSLError:
            vulnerabilities.append({
                'title': 'SSL/TLS Issues',
                'description': 'SSL/TLS connection failed',
                'severity': 'High',
                'type': 'ssl_error'
            })
        except Exception as e:
            vulnerabilities.append({
                'title': 'Connection Error',
                'description': str(e),
                'severity': 'Unknown',
                'type': 'connection_error'
            })

    def check_open_ports(domain):
        nmap = nmap3.NmapScanTechniques()
        try:
            result = nmap.scan_top_ports(domain)
        except Exception as e:
            print(f"Error during scanning: {e}")
        if not result:
            print("No ports found, or there was an error in the nmap code.")
            vulnerabilities.append({
                "title": "Port Scan Error", 
                "description": "No open ports found, or there was an error in the nmap code.",
                "severity": "Unknown",
                "type": "port_scan_error"
            })
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
                            'severity': 'Medium' if port["portid"] not in [80, 443] else 'Info',
                            'type': 'open_port'
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

    # Sort vulnerabilities by severity
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Unknown': 5}
    vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'Unknown'), 5))

    return vulnerabilities