from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from utils import run_domain_check, extract_and_scan_urls, analyze_email_body, hash_attachments

# Define input schemas
class DomainCheckInput(BaseModel):
    sender_email: str = Field(..., description="Sender's email address.")

class URLCheckInput(BaseModel):
    raw_email: str = Field(..., description="Raw email content.")

class ContentCheckInput(BaseModel):
    body: str = Field(..., description="Email body content.")
    sender: str = Field(..., description="Sender's email address.")
    urls: list = Field(..., description="List of URLs extracted from the email.")
    domain_info: dict = Field(..., description="Domain information of the sender.")
    attachments: list = Field(..., description="List of email attachments.")

class AttachmentHashInput(BaseModel):
    attachments: list = Field(..., description="List of email attachments.")

# Define tools
class DomainCheckTool(BaseTool):
    name = "Domain Check Tool"
    description = "Checks the reputation of the sender's domain."
    args_schema = DomainCheckInput

    def _run(self, sender_email: str) -> str:
        return run_domain_check(sender_email)

class URLCheckTool(BaseTool):
    name = "URL Check Tool"
    description = "Extracts and scans URLs from the email content."
    args_schema = URLCheckInput

    def _run(self, raw_email: str) -> str:
        return extract_and_scan_urls(raw_email)

class ContentCheckTool(BaseTool):
    name = "Content Check Tool"
    description = "Analyzes the email body for phishing risk."
    args_schema = ContentCheckInput

    def _run(self, body: str, sender: str, urls: list, domain_info: dict, attachments: list) -> str:
        return analyze_email_body(body, sender, urls, domain_info, attachments)

class AttachmentHashTool(BaseTool):
    name = "Attachment Hash Tool"
    description = "Generates hashes for email attachments."
    args_schema = AttachmentHashInput

    def _run(self, attachments: list) -> str:
        return hash_attachments(attachments)
