from typing import Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from utils import run_domain_check, extract_and_scan_urls, analyze_email_body, hash_attachments, parse_eml_file

# Input schemas
class EmailParserInput(BaseModel):
    eml_path: str = Field(..., description="uploads/sample.eml")

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

# Tool classes
class EmailParserTool(BaseTool):
    name: str = "Email Parser"
    description: str = "Parses an .eml file into sender, subject, body, attachments, raw_message."
    args_schema: Type[BaseModel] = EmailParserInput

    def _run(self, eml_path: str) -> dict:
        return parse_eml_file(eml_path)

class DomainCheckTool(BaseTool):
    name: str = "Domain Check Tool"
    description: str = "Checks the reputation of the sender's domain."
    args_schema: Type[BaseModel] = DomainCheckInput

    def _run(self, sender_email: str) -> str:
        return run_domain_check(sender_email)

class URLCheckTool(BaseTool):
    name: str = "URL Check Tool"
    description: str = "Extracts and scans URLs from the email content."
    args_schema: Type[BaseModel] = URLCheckInput

    def _run(self, raw_email: str) -> str:
        return extract_and_scan_urls(raw_email)

class ContentCheckTool(BaseTool):
    name: str = "Content Check Tool"
    description: str = "Analyzes the email body for phishing risk."
    args_schema: Type[BaseModel] = ContentCheckInput

    def _run(self, body: str, sender: str, urls: list, domain_info: dict, attachments: list) -> str:
        return analyze_email_body(body, sender, urls, domain_info, attachments)

class AttachmentHashTool(BaseTool):
    name: str = "Attachment Hash Tool"
    description: str = "Generates hashes for email attachments."
    args_schema: Type[BaseModel] = AttachmentHashInput

    def _run(self, attachments: list) -> str:
        return hash_attachments(attachments)
