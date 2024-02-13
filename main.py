import pyperclip
import requests
import re

# Your VirusTotal API key
API_KEY = 'YOUR_API_KEY'

# Function to check if the clipboard content is a URL or IP address
def is_valid_content(content):
    url_regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'  # domain
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    ip_regex = re.compile(
        r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    
    return url_regex.match(content) or ip_regex.match(content)

def search_virustotal(content):
    url = f'https://www.virustotal.com/api/v3/urls' if is_valid_content(content) is url_regex else f'https://www.virustotal.com/api/v3/ip_addresses/{content}'
    headers = {
        'x-apikey': API_KEY
    }
    data = {
        'url': content
    }
    response = requests.post(url, headers=headers, data=data) if is_valid_content(content) is url_regex else requests.get(url, headers=headers)
    return response.json()

clipboard_content = pyperclip.paste()

if is_valid_content(clipboard_content):
    print(f"Checking content: {clipboard_content}")
    report = search_virustotal(clipboard_content)
    
    if 'data' in report:
        malicious_count = report['data']['attributes']['last_analysis_stats']['malicious']
        harmless_count = report['data']['attributes']['last_analysis_stats']['harmless']
        report_url = f"https://www.virustotal.com/gui/url/{report['data']['id']}" if is_valid_content(clipboard_content) is url_regex else f"https://www.virustotal.com/gui/ip-address/{clipboard_content}"

        print(f"Malicious: {malicious_count}, Harmless: {harmless_count}")
        print(f"Full report: {report_url}")
    else:
        print("No data found in the report.")
else:
    print("Clipboard content is not a valid URL or IP address.")
