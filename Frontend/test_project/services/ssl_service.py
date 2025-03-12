"""
SSL certificate scanning service for the EASM application.
"""
import socket
import ssl

def get_ssl_info(domain):
    """
    Get SSL certificate information for a domain.
    
    Args:
        domain: Domain name to scan
        
    Returns:
        dict: Dictionary containing SSL certificate information
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'expires': cert['notAfter']
                }
    except Exception as e:
        return {'error': str(e)}