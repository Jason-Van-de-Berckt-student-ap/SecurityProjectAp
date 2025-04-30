import requests
from bs4 import BeautifulSoup
import re
import time
import random

# OUTPUT_FILE = "darkweb_results.json"  # JSON-bestand voor output

def is_valid_onion_link(link):
    # Check if it's a valid onion link (should end with .onion)
    # Accept both http:// and https:// links
    onion_pattern = r'^[a-zA-Z0-9\-\.]+\.onion(/.*)?$'
    return bool(re.match(onion_pattern, link))

def is_interested_link(link, domain):
    # Remove protocol and get the base part of the URL
    clean_link = re.sub(r'^https?://', '', link)
    
    # Get domain without TLD
    domain_base = domain.split('.')[0]
    
    print(f"\n[DEBUG] Checking link: {link}")
    print(f"[DEBUG] Clean link: {clean_link}")
    print(f"[DEBUG] Domain base: {domain_base}")
    
    # Check for interesting patterns
    interesting_keywords = [
        domain_base,  # Company name without TLD
        'admin',
        'login',
        'dashboard',
        'control',
        'panel',
        'system',
        'backup',
        'backups',
        'api',
        'database',
        'server',
        'root',
        'config',
        'setup',
        'install',
        'test',
        'dev',
        'development',
        'staging',
        'clients',
        'email',
        'mail'
    ]
    
    # Check each pattern and print if found
    for keyword in interesting_keywords:
        if keyword.lower() in clean_link.lower():
            print(f"[DEBUG] Found matching pattern: {keyword}")
            print(f"[DEBUG] Pattern '{keyword}' found in '{clean_link}'")
            return True
    
    print(f"[DEBUG] No matching patterns found in '{clean_link}'")
    return False

# Controleer leaks (Dark Web zoekmachine)
def check_ahmia(domain):
    print(f"\n[DEBUG] Starting search for domain: {domain}")
    url = f"https://ahmia.fi/search/?q={domain}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"[DEBUG] Error accessing Ahmia: {response.status_code} - {response.text}")
        return {"Domein": domain, "Fout": f"{response.status_code} - {response.text}"}
    else:
        print("[DEBUG] Successfully accessed Ahmia search engine")
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("a", href=True)
        interested_links = []
        other_links = []
        
        for link in results:
            if ".onion" in link["href"]:
                try:
                    # Extract the actual onion URL from the redirect URL
                    onion_url = link["href"].split("redirect_url=")[-1]
                    # Remove any protocol (http:// or https://) for validation
                    clean_url = re.sub(r'^https?://', '', onion_url)
                    if is_valid_onion_link(clean_url):
                        print(f"\n[DEBUG] Processing onion URL: {onion_url}")
                        # Keep the original protocol (http:// or https://)
                        if is_interested_link(onion_url, domain):
                            interested_links.append(onion_url)
                            print(f"[DEBUG] Added to interested links: {onion_url}")
                        else:
                            other_links.append(onion_url)
                except:
                    continue
        
        print(f"\n[DEBUG] Search complete. Found {len(interested_links)} interested links and {len(other_links)} other links")
        print("[DEBUG] Interested links:", interested_links)
        return {
            'interested_links': interested_links,
            'other_links': other_links
        }