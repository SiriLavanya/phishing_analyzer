from utils.email_parser import parse_eml_file
from tools.email_tools import (
    domain_check_tool,
    url_check_tool,
    content_check_tool,
    attachment_hash_tool
)
from crewai import Task, Crew
from agents import domain_agent, url_agent, content_agent
# Instantiate the tools
domain_check_tool = DomainCheckTool()
url_check_tool = URLCheckTool()
content_check_tool = ContentCheckTool()
attachment_hash_tool = AttachmentHashTool()
def run_analysis(eml_path):
    email_data = parse_eml_file(eml_path)

    # Convert raw email object to string for context
    raw_email_str = email_data["raw_message"].as_string()

    # Create tasks
    domain_task = Task(
        description=f"Check sender: {email_data['from']}",
        agent=domain_agent,
        tools=[domain_check_tool],
        expected_output="Domain reputation and legitimacy",
        context=[f"Sender email: {email_data['from']}"]
    )

    url_task = Task(
        description=f"Extract and scan URLs in email from {email_data['from']}",
        agent=url_agent,
        tools=[url_check_tool],
        expected_output="URL extraction and VirusTotal scan results",
        context=[f"Raw email content: {raw_email_str}"]
    )

    content_task = Task(
        description=f"Analyze phishing tone in email from {email_data['from']}",
        agent=content_agent,
        tools=[content_check_tool],
        expected_output="Phishing risk evaluation using Gemini LLM",
        context=[
            f"Email body: {email_data['body']}",
            f"Sender: {email_data['from']}",
            f"Raw email content: {raw_email_str}",
            f"Attachments: {email_data['attachments']}"
        ]
    )

    # Run the tasks as a crew
    crew = Crew(tasks=[domain_task, url_task, content_task])
    results = crew.run()

    # Print each result
    for r in results:
        print(r)

# ENTRY POINT
if __name__ == "__main__":
    run_analysis(r"C:\Users\siril\OneDrive\Desktop\phishing_email_analyzer\uploads\sample.eml")
