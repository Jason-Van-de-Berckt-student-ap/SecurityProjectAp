import requests
from bs4 import BeautifulSoup
import re

# OUTPUT_FILE = "darkweb_results.json"  # JSON-bestand voor output

def is_valid_onion_link(link):
    # Check if it's a valid onion link (should end with .onion)
    # Accept both http:// and https:// links
    onion_pattern = r'^[a-zA-Z0-9\-\.]+\.onion(/.*)?$'
    return bool(re.match(onion_pattern, link))

# Controleer leaks (Dark Web zoekmachine)
def check_ahmia(domain):
    url = f"https://ahmia.fi/search/?q={domain}"
    headers = {"User-Agent": "DarkWebMonitorScript"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"Domein": domain, "Fout": f"{response.status_code} - {response.text}"}
    else:
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("a", href=True)
        onion_links = []
        for link in results:
            if ".onion" in link["href"]:
                try:
                    # Extract the actual onion URL from the redirect URL
                    onion_url = link["href"].split("redirect_url=")[-1]
                    # Remove any protocol (http:// or https://) for validation
                    clean_url = re.sub(r'^https?://', '', onion_url)
                    if is_valid_onion_link(clean_url):
                        # Keep the original protocol (http:// or https://)
                        onion_links.append(onion_url)
                except:
                    continue
        return {'links': onion_links}