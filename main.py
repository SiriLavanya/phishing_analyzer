from crewai import Crew
from tasks import domain_task, url_task, attach_task, content_task
from utils import parse_eml_file

# Step 1: Load and parse the .eml file
eml_path = 'uploads/sample.eml'  # <-- Change path as needed
email_data = parse_eml_file(eml_path)

sender = email_data["from"]
subject = email_data["subject"]
body = email_data["body"]
attachments = email_data["attachments"]
raw_email = email_data["raw_message"]

# Step 2: Store intermediate results
context = {
    "sender": sender,
    "body": body,
    "attachments": attachments,
    "raw_email": raw_email
}

# Step 3: Initialize Crew
crew = Crew(
    agents=[domain_task.agent, url_task.agent, attach_task.agent, content_task.agent],
    tasks=[domain_task, url_task, attach_task, content_task],
    verbose=True
)

# Step 4: Provide context (as inputs) to agents and run
print("🔍 Starting phishing email analysis...\n")

# Use the kickoff method to start the crew's execution
results = crew.kickoff(inputs=context)

print("\n✅ Final Phishing Verdict:")
print(results)
