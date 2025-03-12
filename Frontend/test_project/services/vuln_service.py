"""
Vulnerability scanning service for the EASM application.
"""
import requests
import concurrent.futures
import nmap3

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