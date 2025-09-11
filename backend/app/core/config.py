"""
Configuration settings for the secure AI data pipeline platform.
"""
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings
from pydantic import Field
from typing import List, Optional
import os


class Settings(BaseSettings):
    """Application settings."""

    # Application
    app_name: str = "Secure AI Data Pipeline"
    version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # Security
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    encryption_key: str = Field(..., env="ENCRYPTION_KEY")
    hash_salt: str = Field(..., env="HASH_SALT")

    # Database
    database_url: str = Field(..., env="DATABASE_URL")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")


    # AI/ML APIs
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(
        default=None, env="ANTHROPIC_API_KEY")

    # Cloud Provider Credentials
    aws_access_key_id: Optional[str] = Field(
        default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(
        default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_default_region: str = Field(
        default="us-east-1", env="AWS_DEFAULT_REGION")

    gcp_project_id: Optional[str] = Field(default=None, env="GCP_PROJECT_ID")
    google_application_credentials: Optional[str] = Field(
        default=None, env="GOOGLE_APPLICATION_CREDENTIALS")

    azure_client_id: Optional[str] = Field(default=None, env="AZURE_CLIENT_ID")
    azure_client_secret: Optional[str] = Field(
        default=None, env="AZURE_CLIENT_SECRET")
    azure_tenant_id: Optional[str] = Field(default=None, env="AZURE_TENANT_ID")
    azure_subscription_id: Optional[str] = Field(
        default=None, env="AZURE_SUBSCRIPTION_ID")

    # CloudQuery
    cloudquery_api_key: Optional[str] = Field(
        default=None, env="CLOUDQUERY_API_KEY")

    # CORS
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "https://localhost:3000"],
        env="CORS_ORIGINS"
    )

    # Rate limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")

    # Security analysis
    max_risk_score: float = Field(default=10.0, env="MAX_RISK_SCORE")
    default_confidence_threshold: float = Field(
        default=0.7, env="DEFAULT_CONFIDENCE_THRESHOLD")

    class Config:
        env_file = ".env"
        case_sensitive = False

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> any:
            if field_name == 'cors_origins':
                return [x.strip() for x in raw_val.split(',')]
            return cls.json_loads(raw_val)


# Global settings instance
settings = Settings()
