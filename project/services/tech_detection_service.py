"""
Technology detection service for the EASM application.
This integrates the enhanced technology detection capabilities.
"""
from services.tech_detection_enhanced import check_tech_vulnerabilities, get_website_technologies

def scan_website_technologies(domain):
    """
    Scan a website for technologies and categorize them.
    
    Args:
        domain (str): Domain name to scan
        
    Returns:
        dict: Detected technologies categorized by type
    """
    return get_website_technologies(domain)

def get_technology_vulnerabilities(domain):
    """
    Check for vulnerabilities based on detected technologies.
    
    Args:
        domain (str): Domain name to scan
        
    Returns:
        list: List of vulnerability dictionaries
    """
    return check_tech_vulnerabilities(domain)

def integrate_tech_vulnerabilities(domain, current_vulnerabilities=None):
    """
    Integrate technology vulnerability scan with existing vulnerability scan results.
    
    Args:
        domain (str): Domain name being scanned
        current_vulnerabilities (list, optional): Existing vulnerability scan results
        
    Returns:
        list: Combined vulnerability scan results
    """
    if current_vulnerabilities is None:
        current_vulnerabilities = []
    
    # Get technology vulnerabilities
    tech_vulnerabilities = check_tech_vulnerabilities(domain)
    
    # Combine results (avoiding duplicates)
    existing_titles = {vuln.get('title', '') for vuln in current_vulnerabilities}
    
    for vuln in tech_vulnerabilities:
        if vuln.get('title', '') not in existing_titles:
            current_vulnerabilities.append(vuln)
    
    return current_vulnerabilities