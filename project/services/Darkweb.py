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

def get_random_user_agent():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    ]
    return random.choice(user_agents)

def get_realistic_headers():
    return {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'DNT': '1'
    }

def is_interested_link(link, domain):
    # Remove protocol and get the base part of the URL
    clean_link = re.sub(r'^https?://', '', link)
    
    # Get domain without TLD
    domain_base = domain.split('.')[0]
    
    print(f"\n[DEBUG] Checking link: {link}")
    print(f"[DEBUG] Clean link: {clean_link}")
    print(f"[DEBUG] Domain base: {domain_base}")
    
    # Check for interesting patterns
    interesting_patterns = [
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
    for keyword in interesting_patterns:
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
    headers = get_realistic_headers()
    response = requests.get(url, headers=headers)
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