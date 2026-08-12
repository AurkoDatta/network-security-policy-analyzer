"""Environment configuration for the analyzer service."""
import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    analyzer_port: int = int(os.environ.get("ANALYZER_PORT", "8000"))
    frontend_port: int = int(os.environ.get("FRONTEND_PORT", "3000"))
    analysis_timeout: int = int(os.environ.get("ANALYSIS_TIMEOUT", "30"))

    @property
    def frontend_origin(self) -> str:
        return f"http://localhost:{self.frontend_port}"


settings = Settings()
