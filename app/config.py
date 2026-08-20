import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

logger = logging.getLogger("agent_waf.config")

class Settings:
    GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./agent_waf.db")
    WAF_ADMIN_API_KEY: str = os.getenv("WAF_ADMIN_API_KEY", "changeme")
    POLICY_FILE: str = os.getenv("POLICY_FILE", "app/policies/waf_policy.yaml")

    # Agent and LLM integration
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")
    OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    AGENT_WAF_URL: str = os.getenv("AGENT_WAF_URL", "http://127.0.0.1:8000")
    AGENT_WAF_TIMEOUT_SECONDS: float = float(os.getenv("AGENT_WAF_TIMEOUT_SECONDS", "5.0"))
    MAX_AGENT_STEPS: int = int(os.getenv("MAX_AGENT_STEPS", "10"))

settings = Settings()

def load_policy_yaml(filepath: str):
    """
    Reads, parses, and validates the WAF security policy YAML.
    Imports Pydantic WAFPolicy dynamically to prevent circular import issues.
    """
    import yaml
    from app.schemas import WAFPolicy

    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {filepath}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML structure in policy file: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to read policy file: {e}") from e

    if data is None:
        data = {}

    try:
        return WAFPolicy.model_validate(data)
    except Exception as e:
        raise ValueError(f"Policy validation failed: {e}") from e
