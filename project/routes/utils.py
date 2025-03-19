"""
Utility functions for the EASM application routes.
"""
import os
import csv
from datetime import datetime

# Constants
ALLOWED_EXTENSIONS = {'txt', 'csv'}

def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension.
    
    Args:
        filename: Name of the file to check
        
    Returns:
        bool: True if the file has an allowed extension, False otherwise
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def export_to_csv(scan_results, domain):
    """
    Export scan results to a CSV file.
    
    Args:
        scan_results: Dictionary containing scan results
        domain: Domain name scanned
        
    Returns:
        str: Filename of the generated CSV file
    """
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    # Generate filename with timestamp
    filename = f'scan_results_{domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    filepath = os.path.join('results', filename)
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Finding', 'Details'])
        
        # Write DNS records
        for record_type, records in scan_results['dns_info'].items():
            for record in records:
                writer.writerow(['DNS Record', record_type, record])
        
        # Write SSL info
        if not isinstance(scan_results['ssl_info'], dict) or 'error' not in scan_results['ssl_info']:
            for key, value in scan_results['ssl_info'].items():
                writer.writerow(['SSL Certificate', key, value])
        
        # Write vulnerabilities
        for vuln in scan_results['vulnerabilities']:
            writer.writerow(['Vulnerability', 
                           f"{vuln['title']} ({vuln['severity']})", 
                           vuln['description']])
        
        # Write subdomains
        for sub in scan_results['subdomains']:
            writer.writerow(['Subdomain', 
                           sub['subdomain'], 
                           f"IP: {sub['ip']}, Status: {sub['status']}"])
        
        # Write related domains
        for domain in scan_results['related_domains']:
            writer.writerow(['Related Domain',
                           f"{domain['domain']} ({domain['confidence']})",
                           f"Type: {domain['relation_type']}, Evidence: {domain['evidence']}"])

    return filename