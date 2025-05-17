from crewai import Agent
#from utils_folder.llm_loader import get_llm

llm = get_llm()

domain_agent = Agent(
    role="Domain Analyst",
    goal="Validate the sender's domain, check DNS records and WHOIS data",
    backstory="You specialize in identifying newly registered or suspicious domains used in phishing.",
    verbose=True,
    allow_delegation=False,
    #llm=llm
)

url_agent = Agent(
    role="URL Reputation Checker",
    goal="Scan and assess the URLs for phishing using VirusTotal",
    backstory="You're an expert in recognizing malicious links often embedded in phishing emails.",
    verbose=True,
    allow_delegation=False,
    #llm=llm
)

content_agent = Agent(
    role="Email Content Analyst",
    goal="Analyze the content and context of the email to detect phishing attempts",
    backstory="You're trained in identifying phishing characteristics in email language and formatting.",
    verbose=True,
    allow_delegation=False,
    #llm=llm
)

attachment_agent = Agent(
    role="Attachment Scanner",
    goal="Hash and analyze file attachments for malware",
    backstory="You help identify harmful attachments by hashing and referencing threat databases.",
    verbose=True,
    allow_delegation=False,
    #llm=llm
)
