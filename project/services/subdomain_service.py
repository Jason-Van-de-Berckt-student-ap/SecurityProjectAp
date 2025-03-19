"""
Subdomain discovery service for the EASM application.
"""
import dns.resolver
import socket
import requests
import concurrent.futures

def find_subdomains(domain):
    """
    Find subdomains for a domain.
    
    Args:
        domain: Domain name to scan
        
    Returns:
        list: List of subdomain dictionaries
    """
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