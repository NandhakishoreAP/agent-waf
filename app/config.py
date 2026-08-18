import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class Settings:
    GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./agent_waf.db")
    WAF_ADMIN_API_KEY: str = os.getenv("WAF_ADMIN_API_KEY", "changeme")
    POLICY_FILE: str = os.getenv("POLICY_FILE", "app/policies/waf_policy.yaml")

settings = Settings()
