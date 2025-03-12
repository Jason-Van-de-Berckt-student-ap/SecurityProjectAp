"""
Domain utilities for the EASM application.
"""
import re
import csv
from io import StringIO

def is_valid_domain(domain):
    """
    Validates if a string is a properly formatted domain name.
    
    Args:
        domain (str): The domain name to validate
        
    Returns:
        bool: True if valid domain name, False otherwise
    """
    if not domain or len(domain) > 255:
        return False
    
    # Regex pattern for domain validation
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_domains_file(file_content, file_extension):
    """
    Validates the uploaded domains file and returns a list of valid domains.
    
    Args:
        file_content (str): Content of the uploaded file
        file_extension (str): The file extension (csv or txt)
        
    Returns:
        tuple: (valid_domains, invalid_domains, error_message)
    """
    valid_domains = []
    invalid_domains = []
    error_message = None
    
    try:
        if file_extension == 'csv':
            # Process CSV file
            csv_file = StringIO(file_content)
            reader = csv.reader(csv_file)
            
            for i, row in enumerate(reader):
                if not row:
                    continue
                
                domain = row[0].strip().lower()
                if domain:
                    if is_valid_domain(domain):
                        if domain not in valid_domains:  # Check for duplicates
                            valid_domains.append(domain)
                    else:
                        invalid_domains.append((domain, i+1))
        else:
            # Process TXT file
            for i, line in enumerate(file_content.splitlines()):
                domain = line.strip().lower()
                if domain:
                    if is_valid_domain(domain):
                        if domain not in valid_domains:  # Check for duplicates
                            valid_domains.append(domain)
                    else:
                        invalid_domains.append((domain, i+1))
    
        if not valid_domains and invalid_domains:
            error_message = f"No valid domains found. All {len(invalid_domains)} domains are invalid."
        
    except Exception as e:
        error_message = f"Error processing file: {str(e)}"
    
    return (valid_domains, invalid_domains, error_message)

def batch_domains(domains, batch_size=5):
    """
    Splits a list of domains into batches to process in parallel.
    
    Args:
        domains (list): List of domain names
        batch_size (int): Number of domains per batch
        
    Returns:
        list: List of domain batches
    """
    return [domains[i:i + batch_size] for i in range(0, len(domains), batch_size)]