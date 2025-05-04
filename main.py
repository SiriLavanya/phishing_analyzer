from utils.email_parser import parse_eml_file
from utils.sender_check import check_sender_domain

# Use raw string for file path to avoid escape issues
file_path = r"C:\Users\siril\OneDrive\Desktop\phishing_email_analyzer\uploads\Siri Lavanya Malladi, Top Openings for Security Analyst.eml"

# Parse the email
email_data = parse_eml_file(file_path)

# Print extracted email data
for key, value in email_data.items():
    if key != 'attachments':
        print(f"{key.capitalize()}: {value}\n")
    else:
        print(f"Attachments: {[name for name, _ in value]}")

# ---------------------------------------
# 🔍 Sender Domain Check
# ---------------------------------------
sender = email_data.get("from")
domain_info = check_sender_domain(sender)

print("\n--- Sender Domain Check ---")
print(f"Domain: {domain_info['domain']}")
print(f"Valid DNS?: {'yes' if domain_info['valid'] else 'No'}")
print(f"Domain Age: {domain_info['age']}")
