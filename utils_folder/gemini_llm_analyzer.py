import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-pro")

def analyze_email_with_gemini(body, sender, urls, domain_info, attachment_info):
    prompt = f"""
You are a cybersecurity analyst reviewing an email for phishing signs.
Analyze this email in a detailed, professional, forensic-style report.

### Email Details:
- Sender Email: {sender}
- Domain Details: {domain_info}
- URLs: {', '.join(urls) if urls else "No URLs found"}
- Attachments: {attachment_info if attachment_info else "No attachments"}

### Email Body:
\"\"\"
{body}
\"\"\"

### Instructions:
1. Break down the body sentence-by-sentence. For each:
   - Identify urgency, impersonation, grammatical issues, or manipulation tactics.
   - Explain the purpose and emotional tone.
   - Check if the intention aligns with the domain’s actual business.
2. Evaluate how suspicious the sender looks based on:
   - Domain name structure (e.g. subdomains, country codes, uncommon TLDs)
   - WHOIS data and domain age
   - Public reputation (use heuristic language if not known)
3. Review the URLs:
   - Are they brand-mimicking, obfuscated, shortened, or flagged by vendors?
   - Could they lead to credential theft or drive-by downloads?
4. Review attachments (if any):
   - Describe them (file names, types, and provided hash if applicable)
   - Recommend if they should be sandboxed
5. Correlate all findings and determine:
   - Is this likely phishing or legitimate?
   - Clearly explain your reasoning using all the above

### Format Output Like:
- 🔍 Sentence-by-Sentence Analysis (at least 10 observations)
- 🧩 Domain Legitimacy
- 🌐 URL Risk Summary
- 📎 Attachment Risk Notes
- 🧠 Final Verdict: Phishing or Legitimate (with reasoning)

Use bullet points, keep it professional, and avoid vague conclusions.
"""
    response = model.generate_content(prompt)
    return response.text
