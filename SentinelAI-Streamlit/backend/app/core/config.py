import os

class Settings:
    PROJECT_NAME: str = "SentinelAI Security Gateway"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"
    USE_MOCK_LLM: bool = os.getenv("USE_MOCK_LLM", "true").lower() == "true"
    # Set ALLOWED_ORIGINS to a comma-separated list in production, including
    # the exact Vercel production domain and any preview domains you need.
    _DEFAULT_ORIGINS = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    ALLOWED_ORIGINS: list[str] = [
        origin.strip().rstrip("/")
        for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ] or _DEFAULT_ORIGINS

settings = Settings()
