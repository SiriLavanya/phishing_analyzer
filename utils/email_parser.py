# utils/email_parser.py

import os
import email
from email import policy
from email.parser import BytesParser

def parse_eml_file(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    email_data = {
        "from": msg['from'],
        "to": msg['to'],
        "subject": msg['subject'],
        "body": "",
        "attachments": [],
        "raw_message": msg
    }

    # Extract email body and attachments
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))

        if "attachment" in content_disposition:
            filename = part.get_filename()
            data = part.get_payload(decode=True)
            email_data["attachments"].append((filename, data))

        elif content_type == "text/plain":
            email_data["body"] += part.get_payload(decode=True).decode(errors='ignore')

    return email_data