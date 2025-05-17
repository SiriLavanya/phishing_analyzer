from tools.sender_check import check_sender_domain
from tools.url_checks import extract_urls, check_virustotal  # ✅ fixed import name
from tools.verdict_engine import analyze_email_with_gemini
from tools.attachment_scanner import get_attachment_hashes

import os
import email
from email import policy
from email.parser import BytesParser

def parse_eml_file(eml_path: str) -> dict:
    """
    Parse an .eml file and extract sender, subject, body, attachments, and raw message.
    Returns a dictionary with all useful elements.
    """
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    parsed_email = {
        "from": msg.get('From'),
        "subject": msg.get('Subject'),
        "body": "",
        "attachments": [],
        "raw_message": msg.as_string()
    }

    # Extract plain text body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' and part.get_payload(decode=True):
                parsed_email["body"] += part.get_payload(decode=True).decode(errors='ignore')
            elif part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                parsed_email["attachments"].append({
                    "filename": filename,
                    "content": content
                })
    else:
        parsed_email["body"] = msg.get_payload(decode=True).decode(errors='ignore')

    return parsed_email

def run_domain_check(sender_email: str) -> dict:
    """Check sender domain validity and age using DNS and WHOIS."""
    return check_sender_domain(sender_email)

def extract_and_scan_urls(raw_email: str) -> list:
    """Extract URLs from raw email content and scan them using VirusTotal."""
    urls = extract_urls(raw_email)
    results = []
    for url in urls:
        vt_result = check_virustotal(url)  # ✅ updated function name
        results.append({ "url": url, "vt_result": vt_result })
    return results

def analyze_email_body(body: str, sender: str, urls: list, domain_info: dict, attachments: list) -> dict:
    """Use Gemini to analyze the email content and generate a phishing verdict."""
    return analyze_email_with_gemini(
        body=body,
        sender=sender,
        urls=urls,
        domain_info=domain_info,
        attachments=attachments
    )

def hash_attachments(attachments: list) -> list:
    """
    Generate SHA-256 hashes for email attachments.
    Input: list of dicts with 'filename' and 'content'
    Output: list of dicts with 'filename' and 'sha256'
    """
    return get_attachment_hashes(attachments)
