import re
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime 

def extract_domain(email_address):
    # Extract domain part from email (e.g., recommendationnc@naukri.com => naukri.com)
    match = re.search(r'@([A-Za-z0-9.-]+)', email_address)
    return match.group(1).lower() if match else None

def is_domain_valid(domain):
    try:
        # Perform a simple DNS check
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        
        # Extract creation and expiration dates
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # Handle lists (some registrars return multiple records)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Format dates if they are datetime objects
        if isinstance(creation_date, datetime):
            creation_date = creation_date.strftime("%Y-%m-%d")
        else:
            creation_date = "Unavailable or malformed creation date"

        if isinstance(expiration_date, datetime):
            expiration_date = expiration_date.strftime("%Y-%m-%d")
        else:
            expiration_date = "Unavailable or malformed expiration date"

        return creation_date, expiration_date
    except Exception as e:
        return f"WHOIS Error: {str(e)}"

def check_sender_domain(sender_email):
    domain = extract_domain(sender_email)
    if not domain:
        return {"domain": None, "valid": False, "age": "Unknown"}

    valid = is_domain_valid(domain)
    creation_date, expiration_date = get_domain_age(domain)
    domain_age = f"Creation Date: {creation_date}, Expiration Date: {expiration_date}"

    return {
        "domain": domain,
        "valid": valid,
        "age": domain_age
    }
