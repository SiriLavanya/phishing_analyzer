import re
import requests
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import os

def extract_urls(email_message):
    urls = set()

    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == "text/html":
            html_content = part.get_payload(decode=True).decode(errors='ignore')
            soup = BeautifulSoup(html_content, 'html.parser')
            for link in soup.find_all('a', href=True):
                urls.add(link['href'])

        elif content_type == "text/plain":
            text_content = part.get_payload(decode=True).decode(errors='ignore')
            found_urls = re.findall(r'(https?://\S+)', text_content)
            urls.update(found_urls)

    return list(urls)

def is_suspicious_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # Check if hostname is IP-based
    is_ip = hostname.replace('.', '').isdigit()

    # Check for common shortened URL services
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
    is_shortened = any(short in hostname for short in shorteners)

    return is_ip or is_shortened

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        return f"Creation Date: {w.creation_date}"
    except Exception as e:
        return f"WHOIS Error: {e}"

def check_virustotal(url):
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        return "VirusTotal Result: VT API key not found"

    headers = {"x-apikey": vt_api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"

    try:
        # Step 1: Submit URL to VT for analysis
        response = requests.post(scan_url, headers=headers, data={"url": url})
        response_json = response.json()

        if response.status_code != 200 or "data" not in response_json:
            return f"VirusTotal Result: Submission failed - {response_json.get('error', 'Unknown error')}"

        # Get analysis ID from response
        analysis_id = response_json["data"]["id"]

        # Step 2: Fetch analysis result
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # Wait for analysis to complete (optional: use loop with sleep if necessary)
        analysis_result = requests.get(analysis_url, headers=headers)
        result_json = analysis_result.json()

        stats = result_json["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        return f"VirusTotal Result: {malicious}/{total} vendors flagged this URL"

    except Exception as e:
        return f"VirusTotal Result: Error - {str(e)}"
def get_urlscan_screenshot(url):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url, "public": "on"})
        scan_id = response.json()["uuid"]
        return f"https://urlscan.io/screenshots/{scan_id}.png"
    except Exception as e:
        return f"Screenshot error: {e}"

