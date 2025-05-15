# utils.py

from utils.sender_check import check_sender_domain
from utils.url_checks import extract_urls, check_virustotal
from utils.verdict_engine import analyze_email_with_gemini
from utils.attachment_scanner import get_attachment_hashes

def run_domain_check(sender_email: str):
    """Check sender domain validity and age using DNS and WHOIS."""
    return check_sender_domain(sender_email)

def extract_and_scan_urls(raw_email):
    """Extract URLs and run VirusTotal scans."""
    urls = extract_urls(raw_email)
    results = []
    for url in urls:
        vt_result = check_virustotal(url)
        results.append(f"{url}: {vt_result}")
    return results

def analyze_email_body(body: str, sender: str, urls: list, domain_info: dict, attachments: list):
    """Use Gemini to analyze email body for phishing risk."""
    return analyze_email_with_gemini(
        body=body,
        sender=sender,
        urls=urls,
        domain_info=domain_info,
        attachments=attachments
    )

def hash_attachments(attachments: list):
    """Return SHA-256 hashes for email attachments."""
    return get_attachment_hashes(attachments)
