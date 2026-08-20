import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

logger = logging.getLogger("agent_waf.config")

class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
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

    # Observability
    OBSERVABILITY_ENABLED: bool = os.getenv("OBSERVABILITY_ENABLED", "true").lower() == "true"
    OBSERVABILITY_MAX_PAGE_SIZE: int = int(os.getenv("OBSERVABILITY_MAX_PAGE_SIZE", "100"))
    SSE_HEARTBEAT_SECONDS: int = int(os.getenv("SSE_HEARTBEAT_SECONDS", "15"))

    def validate_production(self):
        if self.APP_ENV.lower() == "production":
            # 1. Require DATABASE_URL pointing to a production-grade DB (PostgreSQL)
            if not self.DATABASE_URL or "sqlite" in self.DATABASE_URL:
                raise ValueError("DATABASE_URL must be configured with PostgreSQL in production environment")
            
            # 2. Reject dev-only administrative secret configuration
            if self.WAF_ADMIN_API_KEY == "changeme":
                raise ValueError("WAF_ADMIN_API_KEY must not be the default value ('changeme') in production")

            # 3. Ensure API keys / LLM secrets are populated in production if used
            if self.LLM_PROVIDER == "openai" and not self.OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY is required when LLM_PROVIDER is 'openai' in production")
            if self.LLM_PROVIDER == "groq" and not self.GROQ_API_KEY:
                raise ValueError("GROQ_API_KEY is required when LLM_PROVIDER is 'groq' in production")

settings = Settings()
settings.validate_production()

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
