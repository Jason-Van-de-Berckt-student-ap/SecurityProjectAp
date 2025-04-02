import requests
from bs4 import BeautifulSoup

# OUTPUT_FILE = "darkweb_results.json"  # JSON-bestand voor output

def is_valid_onion_link(link):
    return link.startswith("http://") or link.startswith("https://")

# Controleer leaks op Ahmia (Dark Web zoekmachine)
def check_ahmia(domain):
    url = f"https://ahmia.fi/search/?q={domain}"
    headers = {"User-Agent": "DarkWebMonitorScript"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"Domein": domain, "Fout": f"{response.status_code} - {response.text}"}
    else:
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("a", href=True)
        onion_links = [link["href"].split("redirect_url=")[-1] for link in results if ".onion" in link["href"]]
        other_data = [link["href"] for link in results if ".onion" not in link["href"]]
        return {'links':onion_links}