"""
DNS record scanning service for the EASM application.
"""
import dns.resolver

def get_dns_records(domain):
    """
    Get DNS records for a domain.
    
    Args:
        domain: Domain name to scan
        
    Returns:
        dict: Dictionary containing DNS records for the domain
    """
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