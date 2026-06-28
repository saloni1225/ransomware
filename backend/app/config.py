import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./ransomware_defense.db"
    JWT_SECRET: str = "def91823ab0f8c2901a884e9d3d3ef0c74a129d28f84e1bfa82910fae92cb83d"
    ENVIRONMENT: str = "development"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    WEBHOOK_URL: str = ""
    AGENT_SHARED_SECRET: str = "shieldcore_secure_secret_token_2026"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
