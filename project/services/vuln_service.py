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
            # First try with SSL verification
            try:
                response = requests.get(f'https://{domain}', timeout=5, verify=True)
            except requests.exceptions.SSLError:
                # If SSL verification fails, try without it but log a warning
                print(f"Warning: SSL verification failed for {domain}. Proceeding with unverified connection.")
                response = requests.get(f'https://{domain}', timeout=5, verify=False)
            
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': {
                    'message': 'HSTS not set. This header helps prevent protocol downgrade attacks and cookie hijacking.',
                    'severity': 'High',
                    'recommendation': 'Set HSTS header with max-age and includeSubDomains directive.'
                },
                'X-Content-Type-Options': {
                    'message': 'No protection against MIME-type sniffing.',
                    'severity': 'Medium',
                    'recommendation': 'Set X-Content-Type-Options: nosniff'
                },
                'X-Frame-Options': {
                    'message': 'No protection against clickjacking.',
                    'severity': 'Medium',
                    'recommendation': 'Set X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-XSS-Protection': {
                    'message': 'No XSS protection.',
                    'severity': 'Medium',
                    'recommendation': 'Set X-XSS-Protection: 1; mode=block'
                },
                'Content-Security-Policy': {
                    'message': 'No CSP policy.',
                    'severity': 'High',
                    'recommendation': 'Implement a strong Content Security Policy'
                },
                'Referrer-Policy': {
                    'message': 'No Referrer-Policy set.',
                    'severity': 'Low',
                    'recommendation': 'Set Referrer-Policy to control referrer information'
                },
                'Permissions-Policy': {
                    'message': 'No Permissions-Policy set.',
                    'severity': 'Medium',
                    'recommendation': 'Set Permissions-Policy to control browser features'
                },
                'Cache-Control': {
                    'message': 'No Cache-Control header set.',
                    'severity': 'Low',
                    'recommendation': 'Set appropriate Cache-Control headers'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'title': f'Missing {header}',
                        'description': info['message'],
                        'severity': info['severity'],
                        'type': 'security_header',
                        'recommendation': info['recommendation']
                    })
            
            # Check for server version disclosure
            server = headers.get('Server', '')
            if server:
                vulnerabilities.append({
                    'title': 'Server Version Disclosure',
                    'description': f'Server is revealing version information: {server}',
                    'severity': 'Low',
                    'type': 'server_info',
                    'recommendation': 'Remove or obfuscate server version information'
                })
                
        except requests.exceptions.SSLError:
            vulnerabilities.append({
                'title': 'SSL/TLS Issues',
                'description': 'SSL/TLS connection failed. This could indicate certificate problems or weak cipher suites.',
                'severity': 'High',
                'type': 'ssl_error',
                'recommendation': 'Check SSL/TLS configuration and certificate validity'
            })
        except requests.exceptions.ConnectionError:
            vulnerabilities.append({
                'title': 'Connection Error',
                'description': 'Could not establish connection to the server.',
                'severity': 'High',
                'type': 'connection_error',
                'recommendation': 'Verify server is running and accessible'
            })
        except Exception as e:
            vulnerabilities.append({
                'title': 'Header Check Error',
                'description': f'Error checking security headers: {str(e)}',
                'severity': 'Unknown',
                'type': 'header_check_error',
                'recommendation': 'Check server configuration and try again'
            })

    def check_open_ports(domain):
        nmap = nmap3.NmapScanTechniques()
        try:
            # First try a quick scan of common ports
            result = nmap.scan_top_ports(domain)
            
            # If quick scan succeeds, do a more detailed scan
            if result:
                detailed_result = nmap.scan_top_ports(domain, args="-sV -sS -T4")
                
                for ip_address, details in detailed_result.items():
                    if not isinstance(details, dict) or 'ports' not in details:
                        continue
                        
                    for port in details['ports']:
                        if port['state'] == "open":
                            # Get service information
                            service = port.get('service', {})
                            service_name = service.get('name', 'unknown')
                            service_version = service.get('version', 'unknown')
                            
                            # Determine severity based on port and service
                            severity = 'Info'
                            if port['portid'] in ['21', '23', '3389']:  # FTP, Telnet, RDP
                                severity = 'High'
                            elif port['portid'] in ['22', '25', '1433', '3306', '5432']:  # SSH, SMTP, SQL
                                severity = 'Medium'
                            
                            vulnerabilities.append({
                                'title': f'Open Port {port["portid"]} ({service_name})',
                                'description': f'Port {port["portid"]} is open running {service_name} {service_version}. ' +
                                             f'This service should be properly secured and only exposed if necessary.',
                                'severity': severity,
                                'type': 'open_port',
                                'port': port['portid'],
                                'service': service_name,
                                'version': service_version
                            })
        except Exception as e:
            print(f"Error during port scanning: {e}")
            vulnerabilities.append({
                "title": "Port Scan Error", 
                "description": f"Error during port scanning: {str(e)}",
                "severity": "Unknown",
                "type": "port_scan_error"
            })

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