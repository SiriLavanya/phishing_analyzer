from litellm import completion
import os
from dotenv import load_dotenv

load_dotenv()

def get_llm():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in .env")

    # Set env variables for LiteLLM
    os.environ["GOOGLE_API_KEY"] = api_key
    os.environ["LITELLM_PROVIDER"] = "google"
    
    return {
        "model": "gemini-pro",
        "provider": "google"
    }
