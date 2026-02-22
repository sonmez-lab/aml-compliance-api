"""Configuration settings for AML Compliance API."""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from functools import lru_cache
from enum import Enum


class Environment(str, Enum):
    """Application environment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class PricingTier(str, Enum):
    """API pricing tiers."""
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # App
    app_name: str = "AML Compliance API"
    app_version: str = "0.1.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    
    # API Server
    host: str = "0.0.0.0"
    port: int = 8000
    api_prefix: str = "/v1"
    
    # Security
    secret_key: str = Field(
        default="your-secret-key-change-in-production",
        description="Secret key for JWT encoding"
    )
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://localhost/aml_compliance",
        description="PostgreSQL connection URL"
    )
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # Rate Limiting (per tier)
    rate_limit_free: int = 100        # per day
    rate_limit_starter: int = 10000   # per day
    rate_limit_pro: int = 100000      # per day (practically unlimited)
    rate_limit_enterprise: int = -1   # unlimited
    
    # External APIs
    ofac_sdn_url: str = "https://www.treasury.gov/ofac/downloads/sdn.xml"
    basel_aml_api_key: Optional[str] = None
    chainalysis_api_key: Optional[str] = None
    
    # Blockchain APIs
    etherscan_api_key: Optional[str] = None
    trongrid_api_key: Optional[str] = None
    
    # FATF Data
    fatf_data_url: str = "https://www.fatf-gafi.org/content/dam/fatf-gafi/json"
    
    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    
    # Monitoring
    sentry_dsn: Optional[str] = None
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Tier limits configuration
TIER_LIMITS = {
    PricingTier.FREE: {
        "daily_calls": 100,
        "batch_size": 10,
        "features": ["screening"],
        "price_monthly": 0
    },
    PricingTier.STARTER: {
        "daily_calls": 10000,
        "batch_size": 100,
        "features": ["screening", "risk_score", "jurisdiction"],
        "price_monthly": 99
    },
    PricingTier.PRO: {
        "daily_calls": 100000,
        "batch_size": 1000,
        "features": ["screening", "risk_score", "jurisdiction", "monitoring", "sar", "travel_rule"],
        "price_monthly": 499
    },
    PricingTier.ENTERPRISE: {
        "daily_calls": -1,  # unlimited
        "batch_size": 10000,
        "features": ["all"],
        "price_monthly": "custom"
    }
}
