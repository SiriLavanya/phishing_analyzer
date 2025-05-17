from crewai import Task
from agents import domain_agent, url_agent, content_agent, attachment_agent
from email_tools import (
    DomainCheckTool,
    URLCheckTool,
    ContentCheckTool,
    AttachmentHashTool
)

# Task 1: Check sender's domain
domain_task = Task(
    description="Analyze the sender's email domain to check for phishing indicators such as suspicious registration dates, DNS issues, or WHOIS anomalies.",
    expected_output="Dictionary with domain validity, WHOIS info, and red flags if any.",
    agent=domain_agent,
    tools=[DomainCheckTool()],
    async_execution=False
)

# Task 2: Scan URLs in email
url_task = Task(
    description="Extract all URLs from the raw email and check them using VirusTotal or other threat intel sources.",
    expected_output="List of URLs with their VirusTotal reputation and threat indicators.",
    agent=url_agent,
    tools=[URLCheckTool()],
    async_execution=False
)

# Task 3: Hash email attachments
attach_task = Task(
    description="Generate SHA-256 hashes for email attachments to identify known malware or malicious payloads.",
    expected_output="List of hashes (with filenames) that can be used for further threat analysis.",
    agent=attachment_agent,
    tools=[AttachmentHashTool()],
    async_execution=False
)

# Task 4: Perform content analysis and final phishing verdict
content_task = Task(
    description="Analyze the email body, correlate with domain, URL, and attachment findings, and produce a phishing verdict with reasoning using the Gemini LLM.",
    expected_output="Phishing verdict with detailed analysis and justification for the decision.",
    agent=content_agent,
    tools=[ContentCheckTool()],
    async_execution=False
)
