from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ShivShakti Security Command Center"
    api_prefix: str = "/api"
    environment: str = "development"
    database_url: str = "sqlite:///./shivshakti.db"
    jwt_secret: str = "change-me-for-production"
    jwt_algorithm: str = "HS256"
    websocket_channel: str = "security-events"
    allowed_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()

