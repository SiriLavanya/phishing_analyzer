# agents.py

def domain_agent(email_data):
    from tools.email_tools import run_domain_check  # Import inside the function
    """Agent for checking the sender's domain reputation."""
    domain_result = run_domain_check(email_data['from'])
    return domain_result


def url_agent(email_data):
    from tools.email_tools import extract_and_scan_urls  # Import inside the function
    """Agent for extracting and scanning URLs in the email."""
    url_result = extract_and_scan_urls(email_data['raw_message'])
    return url_result


def content_agent(email_data):
    from tools.email_tools import analyze_email_body  # Import inside the function
    """Agent for analyzing email content for phishing risk."""
    content_result = analyze_email_body(
        body=email_data['body'],
        sender=email_data['from'],
        urls=extract_urls(email_data['raw_message']),
        domain_info=run_domain_check(email_data['from']),
        attachments=email_data['attachments']
    )
    return content_result
