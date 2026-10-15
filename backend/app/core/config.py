import os

class Settings:
    PROJECT_NAME: str = "SentinelAI Security Gateway"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"
    USE_MOCK_LLM: bool = os.getenv("USE_MOCK_LLM", "true").lower() == "true"
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

settings = Settings()
