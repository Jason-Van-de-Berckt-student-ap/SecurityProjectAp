"""
Related domain discovery service for the EASM application.
"""
import tldextract
import re
import time
import json
import socket
import ssl
import dns.resolver
import requests
from urllib.parse import urlparse
from difflib import SequenceMatcher
from .domain_utils import is_known_domain

def find_related_domains(domain, brave_api_key=None, timeout=15, max_retries=2):
    """
    Find domains related to the given domain.
    
    Args:
        domain: Domain name to search for related domains
        brave_api_key: API key for Brave Search
        timeout: Request timeout in seconds
        max_retries: Number of retries for failed requests
        
    Returns:
        list: List of related domain dictionaries with Known/Unknown categorization
    """
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
        ])
        
        # Common corporate patterns
        if len(base_domain) > 1:  # Avoid too short names
            patterns.extend([
                f"{base_domain[:3]}",  # First 3 chars
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
                    'evidence': 'Found in SSL certificate SAN',
                    'category': 'Known' if is_known_domain(ssl_domain) else 'Unknown'
                })
        
        # 3. Analyze DNS TXT records
        txt_domains = analyze_dns_txt_records(domain)
        for txt_domain in txt_domains:
            related_domains.append({
                'domain': txt_domain,
                'relation_type': 'DNS TXT Record',
                'confidence': 'Medium',
                'evidence': 'Found in SPF/DMARC records',
                'category': 'Known' if is_known_domain(txt_domain) else 'Unknown'
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
                                        'evidence': f'Found in Brave search results for "{domain}"',
                                        'category': 'Known' if is_known_domain(found_domain) else 'Unknown'
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
        to_remove = set()
        for found_domain in found_domains:
            relation = "Unknown Relation"
            confidence = "Unknown"
            
            if found_domain.endswith(f".{domain}"):
                to_remove.add(found_domain)  # Voeg toe aan de lijst van te verwijderen items
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
                    'evidence': 'Found in Certificate Transparency logs',
                    'category': 'Known' if is_known_domain(found_domain) else 'Unknown'
                })

        # Verwijder de gemarkeerde items na de iteratie
        found_domains -= to_remove

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