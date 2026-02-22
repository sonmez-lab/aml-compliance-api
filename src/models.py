"""Database models for AML Compliance API."""

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional
from sqlalchemy import (
    Column, String, DateTime, Numeric, Boolean, 
    Integer, ForeignKey, Text, Index, Enum as SQLEnum
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID
import uuid


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class RiskLevel(str, Enum):
    """Risk level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    PROHIBITED = "prohibited"


class SanctionsSource(str, Enum):
    """Source of sanctions data."""
    OFAC = "ofac"
    EU = "eu"
    UK = "uk"
    UN = "un"
    FATF = "fatf"


class BlockchainType(str, Enum):
    """Supported blockchain types."""
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    TRON = "tron"
    POLYGON = "polygon"
    BSC = "bsc"
    SOLANA = "solana"


# ============ User & API Key Management ============

class User(Base):
    """API user account."""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Profile
    company_name = Column(String(255))
    full_name = Column(String(255))
    
    # Subscription
    tier = Column(String(32), default="free")
    stripe_customer_id = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    api_keys = relationship("APIKey", back_populates="user")


class APIKey(Base):
    """API key for authentication."""
    
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    key_hash = Column(String(255), nullable=False, index=True)
    key_prefix = Column(String(16), nullable=False)  # For display: "aml_xxxx..."
    name = Column(String(128))
    
    # Permissions
    scopes = Column(JSONB, default=["read", "screen"])
    
    # Usage tracking
    last_used_at = Column(DateTime)
    total_requests = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")


# ============ Screening & Sanctions ============

class ScreeningRequest(Base):
    """Log of screening API requests."""
    
    __tablename__ = "screening_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Request details
    address = Column(String(128), nullable=False, index=True)
    blockchain = Column(SQLEnum(BlockchainType))
    
    # Results
    is_sanctioned = Column(Boolean, default=False)
    risk_level = Column(SQLEnum(RiskLevel))
    risk_score = Column(Numeric(5, 2))  # 0-100
    
    # Matches
    sanctions_matches = Column(JSONB, default=[])
    
    # Response time
    response_time_ms = Column(Integer)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index("ix_screening_user_date", "user_id", "created_at"),
    )


class SanctionedAddress(Base):
    """Cached sanctioned cryptocurrency addresses."""
    
    __tablename__ = "sanctioned_addresses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String(128), unique=True, nullable=False, index=True)
    blockchain = Column(SQLEnum(BlockchainType))
    
    # Source
    source = Column(SQLEnum(SanctionsSource), nullable=False)
    source_id = Column(String(128))  # e.g., SDN ID
    
    # Entity info
    entity_name = Column(String(512))
    entity_type = Column(String(64))
    program = Column(String(128))
    country = Column(String(64))
    
    # Status
    designation_date = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    # Metadata
    metadata = Column(JSONB, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============ Risk Assessment ============

class RiskAssessment(Base):
    """Detailed risk assessment record."""
    
    __tablename__ = "risk_assessments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Subject
    address = Column(String(128), nullable=False, index=True)
    blockchain = Column(SQLEnum(BlockchainType))
    
    # Overall score
    risk_score = Column(Numeric(5, 2), nullable=False)
    risk_level = Column(SQLEnum(RiskLevel), nullable=False)
    
    # Factor breakdown
    sanctions_score = Column(Numeric(5, 2), default=0)
    jurisdiction_score = Column(Numeric(5, 2), default=0)
    behavior_score = Column(Numeric(5, 2), default=0)
    counterparty_score = Column(Numeric(5, 2), default=0)
    
    # Details
    factors = Column(JSONB, default={})
    recommendations = Column(JSONB, default=[])
    
    created_at = Column(DateTime, default=datetime.utcnow)


class JurisdictionRisk(Base):
    """Country/jurisdiction risk profiles."""
    
    __tablename__ = "jurisdiction_risks"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    country_code = Column(String(3), unique=True, nullable=False, index=True)
    country_name = Column(String(128), nullable=False)
    
    # FATF status
    fatf_status = Column(String(32))  # "compliant", "grey_list", "black_list"
    fatf_last_updated = Column(DateTime)
    
    # Risk scores
    overall_risk_score = Column(Numeric(5, 2))
    basel_aml_index = Column(Numeric(5, 2))
    corruption_index = Column(Numeric(5, 2))
    
    # Crypto regulation
    crypto_legal_status = Column(String(32))  # "legal", "restricted", "banned"
    has_travel_rule = Column(Boolean, default=False)
    has_vasp_licensing = Column(Boolean, default=False)
    
    # Sanctions
    is_ofac_sanctioned = Column(Boolean, default=False)
    is_eu_sanctioned = Column(Boolean, default=False)
    
    # Metadata
    metadata = Column(JSONB, default={})
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============ Compliance Reporting ============

class SARDraft(Base):
    """Suspicious Activity Report draft."""
    
    __tablename__ = "sar_drafts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Subject
    subject_address = Column(String(128))
    subject_name = Column(String(255))
    
    # Report content
    narrative = Column(Text)
    suspicious_activity_type = Column(String(128))
    amount_involved = Column(Numeric(18, 2))
    currency = Column(String(16))
    
    # Timeline
    activity_start_date = Column(DateTime)
    activity_end_date = Column(DateTime)
    
    # Status
    status = Column(String(32), default="draft")  # draft, review, submitted
    
    # Supporting data
    transactions = Column(JSONB, default=[])
    risk_indicators = Column(JSONB, default=[])
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TravelRuleCheck(Base):
    """Travel Rule compliance check."""
    
    __tablename__ = "travel_rule_checks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Transaction
    transaction_hash = Column(String(128))
    blockchain = Column(SQLEnum(BlockchainType))
    amount = Column(Numeric(36, 18))
    amount_usd = Column(Numeric(18, 2))
    
    # Parties
    originator_vasp = Column(String(255))
    originator_address = Column(String(128))
    beneficiary_vasp = Column(String(255))
    beneficiary_address = Column(String(128))
    
    # Compliance
    threshold_exceeded = Column(Boolean)  # > $3000 typically
    travel_rule_required = Column(Boolean)
    compliance_status = Column(String(32))  # "compliant", "missing_info", "not_required"
    
    # Missing fields
    missing_fields = Column(JSONB, default=[])
    
    created_at = Column(DateTime, default=datetime.utcnow)


# ============ API Usage ============

class APIUsage(Base):
    """Daily API usage tracking."""
    
    __tablename__ = "api_usage"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    date = Column(DateTime, nullable=False)
    
    # Counts by endpoint
    screening_calls = Column(Integer, default=0)
    risk_score_calls = Column(Integer, default=0)
    jurisdiction_calls = Column(Integer, default=0)
    sar_calls = Column(Integer, default=0)
    travel_rule_calls = Column(Integer, default=0)
    
    # Totals
    total_calls = Column(Integer, default=0)
    
    __table_args__ = (
        Index("ix_usage_user_date", "user_id", "date", unique=True),
    )
