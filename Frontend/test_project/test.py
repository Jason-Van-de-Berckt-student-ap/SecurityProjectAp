import requests
from config import BRAVE_API_KEY

def test_brave_api(api_key, query):
    """Test Brave Search API directly"""
    url = "https://api.search.brave.com/res/v1/web/search"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "X-Subscription-Token": api_key
    }
    params = {
        "q": query,
        "count": 10  # Start with a smaller count for testing
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {response.headers}")
        
        if response.status_code == 200:
            data = response.json()
            print("\nSearch Results:")
            if 'web' in data and 'results' in data['web']:
                for result in data['web']['results'][:3]:  # Show first 3 results
                    print(f"- {result.get('url', 'No URL')}")
            return data
        else:
            print(f"Error Response: {response.text}")
            return None
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return None

# Example usage:
if __name__ == "__main__":
    API_KEY = BRAVE_API_KEY
    print(API_KEY)
    test_query = '"New Wave Group" official website'
    
    print("Testing Brave Search API...")
    results = test_brave_api(API_KEY, test_query)