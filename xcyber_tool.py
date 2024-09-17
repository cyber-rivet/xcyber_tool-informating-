import requests
from urllib.parse import urlparse
import socket
import sys
import time
import argparse
from bs4 import BeautifulSoup
import re
import json

# API endpoints for domain information and IP geolocation
WHOIS_API_URL = "https://api.whois.vu/"
IP_GEOLOCATION_API_URL = "https://ipinfo.io/"

# Function to display the animated startup message
def print_startup_message():
    banner = """
    ====================================
    AI Link Analysis Tool
    Made by Cyber Rivet
    ====================================
    """
    animation = "Starting xCyber Tool..."
    for char in banner:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.05)
    print("\n")

    for char in animation:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.05)
    print("\n")

# Function to get the IP address of the domain
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        return f"Error resolving IP: {str(e)}"

# Function to get domain hosting information
def get_domain_info(domain):
    try:
        response = requests.get(f"{WHOIS_API_URL}?domain={domain}")
        if response.status_code == 200:
            data = response.json()
            hosting = data.get('hosting', 'Unknown')
            registrar = data.get('registrar', 'Unknown')
            return hosting, registrar
        else:
            return 'Error fetching domain info', 'Unknown'
    except requests.RequestException as e:
        return f"Error: {str(e)}", 'Unknown'

# Function to get IP geolocation information
def get_geolocation(ip_address):
    try:
        response = requests.get(f"{IP_GEOLOCATION_API_URL}{ip_address}/json/")
        if response.status_code == 200:
            data = response.json()
            return data.get('city', 'Unknown'), data.get('region', 'Unknown'), data.get('country', 'Unknown')
        else:
            return 'Unknown', 'Unknown', 'Unknown'
    except requests.RequestException as e:
        return f"Error: {str(e)}", 'Unknown', 'Unknown'

# Function to extract meta information from the page
def extract_meta_information(soup):
    meta_info = {}
    meta_tags = soup.find_all('meta')
    for tag in meta_tags:
        name = tag.get('name')
        content = tag.get('content')
        if name and content:
            meta_info[name] = content
    return meta_info

# Function to extract contact information from the page
def extract_contact_information(soup):
    contact_info = {}
    phone_numbers = re.findall(r'\+?\d[\d -]{7,}\d', soup.get_text())
    email_addresses = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())

    if phone_numbers:
        contact_info['Phone Numbers'] = phone_numbers
    if email_addresses:
        contact_info['Email Addresses'] = email_addresses

    return contact_info

# Function to classify the URL based on known indicators
def classify_url(url):
    tracking_patterns = [
        r'track',
        r'analytics',
        r'adservice',
        r'click',
        r'iplogger',
        r'location'
    ]
    phishing_patterns = [
        r'login',
        r'account',
        r'update',
        r'verify',
        r'confirm'
    ]
    known_phishing_domains = [
        r'phishingsite',
        r'fakebank',
        r'scamsite'
    ]

    parsed_url = urlparse(url)
    path_and_params = parsed_url.path + parsed_url.query

    for pattern in tracking_patterns:
        if re.search(pattern, path_and_params, re.IGNORECASE):
            return 'Tracking'
    for pattern in phishing_patterns:
        if re.search(pattern, path_and_params, re.IGNORECASE):
            return 'Phishing'
    for known_domain in known_phishing_domains:
        if re.search(known_domain, parsed_url.netloc, re.IGNORECASE):
            return 'Phishing'

    return 'Unknown'

# Function to analyze the URL
def analyze_url(url, use_proxy=True):
    if not url.startswith(('http://', 'https://')):
        return {
            'URL': url,
            'Domain': 'Unknown',
            'IP Address': 'Unknown',
            'Status Code': 'Error',
            'Content Type': 'Unknown',
            'Potential Issues': 'Invalid URL: No scheme supplied. Perhaps you meant https://?',
            'Hosting': 'Unknown',
            'Registrar': 'Unknown',
            'Location': 'Unknown',
            'City': 'Unknown',
            'Region': 'Unknown',
            'Country': 'Unknown',
            'Meta Information': 'N/A',
            'Contact Information': 'N/A',
            'Browser Compatibility': 'Unknown'
        }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Referer': 'https://www.google.com'
    }

    proxies = {
        'http': 'http://your-proxy-address',
        'https': 'https://your-proxy-address',
    } if use_proxy else None

    try:
        time.sleep(5)
        response = requests.get(url, headers=headers, proxies=proxies, timeout=15)

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        status_code = response.status_code
        content_type = response.headers.get('Content-Type', 'Unknown')

        ip_address = get_ip_address(domain)
        hosting, registrar = get_domain_info(domain)
        city, region, country = get_geolocation(ip_address)

        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        meta_info = extract_meta_information(soup)
        contact_info = extract_contact_information(soup)

        classification = classify_url(url)

        potential_issues = 'None detected'
        if classification == 'Tracking':
            potential_issues = 'Possible tracking domain detected'
        elif classification == 'Phishing':
            potential_issues = 'Possible phishing attempt detected'
        else:
            malware_indicators = ['malware', 'virus', 'trojan', 'ransomware']
            if any(indicator in content.lower() for indicator in malware_indicators):
                potential_issues = 'Possible malware detected in the content'

        browser_compatibility = 'Likely compatible with major browsers' if 'text/html' in content_type else 'Not compatible with major browsers'

        analysis_result = {
            'URL': url,
            'Domain': domain,
            'IP Address': ip_address,
            'Status Code': status_code,
            'Content Type': content_type,
            'Potential Issues': potential_issues,
            'Hosting': hosting,
            'Registrar': registrar,
            'Location': f'{city}, {region}, {country}',
            'City': city,
            'Region': region,
            'Country': country,
            'Meta Information': meta_info,
            'Contact Information': contact_info,
            'Browser Compatibility': browser_compatibility
        }

        if 'text/html' not in content_type:
            analysis_result['Potential Issues'] = 'Non-HTML content detected'
        if status_code != 200:
            analysis_result['Potential Issues'] = f'Error: Status code {status_code}'

    except requests.RequestException as e:
        if use_proxy:
            print("Proxy error detected. Trying without proxy...")
            return analyze_url(url, use_proxy=False)
        else:
            analysis_result = {
                'URL': url,
                'Domain': 'Unknown',
                'IP Address': 'Unknown',
                'Status Code': 'Error',
                'Content Type': 'Unknown',
                'Potential Issues': f"Request exception: {str(e)}",
                'Hosting': 'Unknown',
                'Registrar': 'Unknown',
                'Location': 'Unknown',
                'City': 'Unknown',
                'Region': 'Unknown',
                'Country': 'Unknown',
                'Meta Information': 'N/A',
                'Contact Information': 'N/A',
                'Browser Compatibility': 'Unknown'
            }

    return analysis_result

# Function to display analysis result
def display_result(result):
    print(f"\n{'='*30}")
    print(f"URL: {result['URL']}")
    print(f"Domain: {result['Domain']}")
    print(f"IP Address: {result['IP Address']}")
    print(f"Status Code: {result['Status Code']}")
    print(f"Content Type: {result['Content Type']}")
    print(f"Potential Issues: {result['Potential Issues']}")
    print(f"Hosting: {result['Hosting']}")
    print(f"Registrar: {result['Registrar']}")
    print(f"Location: {result['Location']}")
    print(f"City: {result['City']}")
    print(f"Region: {result['Region']}")
    print(f"Country: {result['Country']}")
    print(f"Meta Information: {result['Meta Information']}")
    print(f"Contact Information: {result['Contact Information']}")
    print(f"Browser Compatibility: {result['Browser Compatibility']}")
    print(f"{'='*30}\n")

# Main function
def main():
    parser = argparse.ArgumentParser(description='Analyze a URL for potential issues.')
    parser.add_argument('url', type=str, help='URL to analyze')
    args = parser.parse_args()

    print_startup_message()

    url = args.url.strip()
    result = analyze_url(url)
    display_result(result)

if __name__ == "__main__":
    main()
