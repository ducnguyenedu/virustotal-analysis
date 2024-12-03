# File: virustotal_analysis.py
import requests  # Library for sending HTTP requests
import pandas as pd  # Library for managing and processing tabular data

# ==== CONSTANTS ====
API_KEY = 'YOUR_VIRUS_TOTAL_API_KEY'  # VirusTotal API key
BASE_URL = 'https://www.virustotal.com/api/v3'  # Base URL for VirusTotal API
SEARCH_URL = f"{BASE_URL}/intelligence/search"  # Endpoint for entity searches
REFERRER_FILES_URL = f"{BASE_URL}/urls/{{}}/referrer_files"  # Endpoint for retrieving related files
QUERY = 'entity:file p:5+ (embedded_domain:api.openai.com or behaviour_network:api.openai.com)'  # Search query
HEADERS = {'x-apikey': API_KEY}  # HTTP headers for API authentication
LIMIT = 100  # Maximum number of results to retrieve

# ==== FUNCTIONS ====
def fetch_search_results(query, limit):
    """
    Sends a query to VirusTotal to search for entities.
    :param query: Search query (str)
    :param limit: Maximum number of results to fetch (int)
    :return: List of entities retrieved from the API
    """
    params = {'query': query, 'limit': limit}
    response = requests.get(SEARCH_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get('data', [])
    else:
        raise ValueError(f"Error {response.status_code}: {response.text}")

def fetch_referrer_files(file_id):
    """
    Retrieves detailed information about related files from VirusTotal.
    :param file_id: The ID of the entity file (str)
    :return: List of related files
    """
    url = REFERRER_FILES_URL.format(file_id)
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json().get('data', [])
    else:
        print(f"Warning: Unable to retrieve referrer files for {file_id} - {response.status_code}")
        return []

def filter_malicious_files(file_data):
    """
    Filters files with high malicious detection scores.
    :param file_data: Detailed file data (list)
    :return: List of SHA256 hashes of malicious files
    """
    return [
        item['attributes']['sha256']
        for item in file_data
        if item['attributes']['last_analysis_stats']['malicious'] > 1
    ]

# ==== MAIN FUNCTION ====
def main():
    """
    Main function to execute the process of searching, filtering, and displaying malicious files.
    """
    try:
        # Step 1: Search for entities related to api.openai.com
        search_results = fetch_search_results(QUERY, LIMIT)
        
        # Step 2: Retrieve related file details and filter malicious files
        malware_hashes = []  # List to store SHA256 hashes of malicious files
        for result in search_results:
            file_id = result['id']  # Extract file ID from search results
            referrer_files = fetch_referrer_files(file_id)  # Fetch related file details
            malware_hashes.extend(filter_malicious_files(referrer_files))  # Filter and add malicious files

        # Step 3: Display the list of malicious files
        if malware_hashes:
            print("List of malicious files interacting with the OpenAI API:")
            for sha256 in malware_hashes:
                print(f"- {sha256}")
        else:
            print("No highly malicious files were found.")
    
    except Exception as e:
        # Handle any errors that occur during execution
        print(f"An error occurred: {e}")

# ==== ENTRY POINT ====
if __name__ == "__main__":
    main()
