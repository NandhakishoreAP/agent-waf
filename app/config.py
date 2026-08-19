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
