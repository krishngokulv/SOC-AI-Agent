"""Configuration loader from environment variables."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""

    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")

    # Database
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "./soc_agent.db")
    DATABASE_URL: str = f"sqlite+aiosqlite:///{DATABASE_PATH}"

    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Enrichment cache TTL in seconds (24 hours)
    CACHE_TTL: int = 86400

    # Report output directory
    REPORT_DIR: Path = Path(os.getenv("REPORT_DIR", "./reports_output"))

    @classmethod
    def init(cls) -> None:
        """Initialize configuration and create necessary directories."""
        cls.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def has_key(cls, key_name: str) -> bool:
        """Check if an API key is configured."""
        value = getattr(cls, key_name, "")
        return bool(value and value.strip())


config = Config()
