from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://aegis:aegis@postgres:5432/aegisops"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str                      # required: no insecure default
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    cors_origins: str = "http://localhost:5173"
    ai_provider: str = "none"            # none | openai | anthropic
    ai_api_key: str = ""
    ai_model: str = ""
    ai_base_url: str = ""
    max_upload_mb: int = 25
    sync_ingest_limit: int = 2000        # larger uploads go to Celery
    demo_mode: bool = True

settings = Settings()
