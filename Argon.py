import re
import requests

def is_phishing(url):
    # Check for common phishing techniques
    if 'http://' in url or 'https://' in url:
        return True
    
    # Check for IP addresses in the domain
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url):
        return True
    
    # Check for long or suspicious URLs
    if len(url) > 75 or 'bit.ly' in url or 'tinyurl.com' in url:
        return True
    
    try:
        # Check if the domain is registered recently
        whois_info = requests.get(f'https://www.whoisxmlapi.com/whoisserver/WhoisOutput?domainName={url}&outputFormat=JSON&registryInfoOnly=false&hostName=&outputLanguage=en&mode=XML').json()
        creation_date = whois_info['WhoisRecord']['createdDate']
        if creation_date and int(creation_date[:4]) >= 2023:
            return True
    except:
        pass
    
    return False

# Example usage
url = input("Enter the URL: ")
if is_phishing(url):
    print("The URL is likely a phishing attempt.")
else:
    print("The URL does not appear to be a phishing attempt.")