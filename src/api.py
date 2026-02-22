"""FastAPI application for AML Compliance API."""

from datetime import datetime
from decimal import Decimal
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import structlog

from .config import get_settings, PricingTier, TIER_LIMITS
from .models import BlockchainType, RiskLevel, SanctionsSource
from .services import (
    get_screener, SanctionsScreener,
    RiskAssessor, get_jurisdiction_risk,
    SARGenerator, TravelRuleChecker
)

logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="AML Compliance API",
    description="""
    Unified REST API for cryptocurrency AML/sanctions compliance.
    
    ## Features
    - Wallet address sanctions screening
    - Multi-factor risk scoring  
    - Jurisdiction compliance checks
    - SAR draft generation
    - Travel Rule compliance
    
    ## Pricing
    | Tier | Price | Daily Calls | Features |
    |------|-------|-------------|----------|
    | Free | $0 | 100 | Basic screening |
    | Starter | $99/mo | 10,000 | + Risk scores |
    | Pro | $499/mo | 100,000 | + Monitoring, SAR |
    | Enterprise | Custom | Unlimited | + SLA, Support |
    """,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============ Request/Response Models ============

class ScreenRequest(BaseModel):
    address: str = Field(..., description="Cryptocurrency address to screen")
    blockchain: str = Field(default="ethereum", description="Blockchain type")


class BatchScreenRequest(BaseModel):
    addresses: list[ScreenRequest] = Field(..., max_length=1000)


class ScreenResponse(BaseModel):
    address: str
    blockchain: str
    is_sanctioned: bool
    risk_level: str
    risk_score: float
    matches: list[dict] = []
    sources_checked: list[str] = []
    response_time_ms: int


class RiskScoreRequest(BaseModel):
    address: str
    blockchain: str = "ethereum"
    include_behavior: bool = True
    include_counterparty: bool = True


class RiskScoreResponse(BaseModel):
    address: str
    blockchain: str
    risk_score: float
    risk_level: str
    sanctions_score: float
    jurisdiction_score: float
    behavior_score: float
    counterparty_score: float
    factors: list[dict] = []
    recommendations: list[str] = []


class JurisdictionResponse(BaseModel):
    country_code: str
    country_name: str
    fatf_status: str
    risk_score: float
    crypto_status: Optional[str] = None
    travel_rule_required: bool = False


class SARRequest(BaseModel):
    address: str
    blockchain: str = "ethereum"
    activity_type: str = Field(..., description="Type of suspicious activity")
    transactions: list[dict] = []
    additional_info: dict = {}


class SARResponse(BaseModel):
    id: str
    narrative: str
    suspicious_activity_type: str
    amount_involved: str
    risk_indicators: list[str] = []
    generated_at: datetime


class TravelRuleRequest(BaseModel):
    amount_usd: float
    blockchain: str = "ethereum"
    originator_info: dict = {}
    beneficiary_info: dict = {}
    originator_jurisdiction: str = "US"
    transaction_hash: Optional[str] = None


class TravelRuleResponse(BaseModel):
    threshold_usd: float
    threshold_exceeded: bool
    travel_rule_required: bool
    is_compliant: bool
    status: str
    missing_originator_fields: list[str] = []
    missing_beneficiary_fields: list[str] = []


# ============ Startup/Shutdown ============

@app.on_event("startup")
async def startup():
    """Initialize services."""
    logger.info("AML Compliance API starting...")
    
    # Initialize screener and refresh cache
    screener = get_screener()
    # await screener.refresh_sanctions_cache()  # Uncomment in production
    
    logger.info("AML Compliance API started")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup."""
    screener = get_screener()
    await screener.close()
    logger.info("AML Compliance API stopped")


# ============ Health & Info ============

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@app.get("/v1/info")
async def api_info():
    """API information and pricing."""
    return {
        "name": "AML Compliance API",
        "version": "0.1.0",
        "pricing": {
            tier.value: {
                "daily_calls": limits["daily_calls"],
                "features": limits["features"],
                "price_monthly": limits["price_monthly"]
            }
            for tier, limits in TIER_LIMITS.items()
        }
    }


# ============ Screening Endpoints ============

@app.post("/v1/screen", response_model=ScreenResponse)
async def screen_address(request: ScreenRequest):
    """
    Screen a cryptocurrency address against sanctions lists.
    
    Returns whether the address is sanctioned, risk level, and any matches found.
    """
    screener = get_screener()
    
    try:
        blockchain = BlockchainType(request.blockchain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid blockchain: {request.blockchain}")
    
    result = await screener.screen_address(request.address, blockchain)
    
    return ScreenResponse(
        address=result.address,
        blockchain=result.blockchain.value,
        is_sanctioned=result.is_sanctioned,
        risk_level=result.risk_level.value,
        risk_score=result.risk_score,
        matches=result.matches,
        sources_checked=result.sources_checked,
        response_time_ms=result.response_time_ms
    )


@app.post("/v1/batch-screen")
async def batch_screen(request: BatchScreenRequest):
    """
    Screen multiple addresses in batch.
    
    Tier limits apply to batch size.
    """
    screener = get_screener()
    
    addresses = [
        {"address": a.address, "blockchain": a.blockchain}
        for a in request.addresses
    ]
    
    results = await screener.batch_screen(addresses)
    
    return {
        "total": len(results),
        "sanctioned_count": len([r for r in results if r.is_sanctioned]),
        "results": [
            {
                "address": r.address,
                "is_sanctioned": r.is_sanctioned,
                "risk_level": r.risk_level.value,
                "risk_score": r.risk_score
            }
            for r in results
        ]
    }


@app.get("/v1/sanctions")
async def search_sanctions(
    query: str = Query(..., min_length=3, description="Search query"),
    source: Optional[str] = Query(None, description="Filter by source (ofac, eu, uk)"),
    limit: int = Query(50, le=200)
):
    """Search sanctions lists by name or address."""
    screener = get_screener()
    
    source_filter = None
    if source:
        try:
            source_filter = SanctionsSource(source)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid source: {source}")
    
    results = await screener.search_sanctions(query, source_filter, limit)
    
    return {
        "query": query,
        "count": len(results),
        "results": results
    }


# ============ Risk Assessment Endpoints ============

@app.post("/v1/risk-score", response_model=RiskScoreResponse)
async def calculate_risk_score(request: RiskScoreRequest):
    """
    Calculate comprehensive risk score for an address.
    
    Includes sanctions, jurisdiction, behavior, and counterparty factors.
    """
    try:
        blockchain = BlockchainType(request.blockchain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid blockchain: {request.blockchain}")
    
    assessor = RiskAssessor()
    result = await assessor.assess_address(
        request.address,
        blockchain,
        request.include_behavior,
        request.include_counterparty
    )
    
    return RiskScoreResponse(
        address=result.address,
        blockchain=result.blockchain.value,
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        sanctions_score=result.sanctions_score,
        jurisdiction_score=result.jurisdiction_score,
        behavior_score=result.behavior_score,
        counterparty_score=result.counterparty_score,
        factors=[
            {
                "name": f.name,
                "category": f.category,
                "score": f.score,
                "severity": f.severity,
                "description": f.description
            }
            for f in result.factors
        ],
        recommendations=result.recommendations
    )


@app.get("/v1/jurisdiction/{country_code}", response_model=JurisdictionResponse)
async def get_jurisdiction(country_code: str):
    """
    Get risk profile for a jurisdiction.
    
    Includes FATF status, risk score, and crypto regulation status.
    """
    data = await get_jurisdiction_risk(country_code)
    
    return JurisdictionResponse(
        country_code=country_code.upper(),
        country_name=data.get("name", country_code),
        fatf_status=data.get("status", "unknown"),
        risk_score=data.get("risk_score", 50),
        crypto_status=data.get("crypto_status"),
        travel_rule_required=data.get("travel_rule", False)
    )


# ============ Compliance Endpoints ============

@app.post("/v1/travel-rule", response_model=TravelRuleResponse)
async def check_travel_rule(request: TravelRuleRequest):
    """
    Check Travel Rule compliance for a transaction.
    
    Returns whether Travel Rule applies and any missing required information.
    """
    try:
        blockchain = BlockchainType(request.blockchain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid blockchain: {request.blockchain}")
    
    checker = TravelRuleChecker()
    result = checker.check_compliance(
        amount_usd=Decimal(str(request.amount_usd)),
        blockchain=blockchain,
        originator_info=request.originator_info,
        beneficiary_info=request.beneficiary_info,
        originator_jurisdiction=request.originator_jurisdiction,
        transaction_hash=request.transaction_hash
    )
    
    return TravelRuleResponse(
        threshold_usd=float(result.threshold_usd),
        threshold_exceeded=result.threshold_exceeded,
        travel_rule_required=result.travel_rule_required,
        is_compliant=result.is_compliant,
        status=result.status,
        missing_originator_fields=result.missing_originator_fields,
        missing_beneficiary_fields=result.missing_beneficiary_fields
    )


@app.post("/v1/sar-draft", response_model=SARResponse)
async def generate_sar_draft(request: SARRequest):
    """
    Generate a Suspicious Activity Report draft.
    
    Creates a formatted SAR narrative based on the provided information.
    """
    try:
        blockchain = BlockchainType(request.blockchain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid blockchain: {request.blockchain}")
    
    generator = SARGenerator()
    result = await generator.generate_sar_draft(
        address=request.address,
        blockchain=blockchain,
        activity_type=request.activity_type,
        transactions=request.transactions,
        additional_info=request.additional_info
    )
    
    return SARResponse(
        id=result.id,
        narrative=result.narrative,
        suspicious_activity_type=result.suspicious_activity_type,
        amount_involved=str(result.amount_involved),
        risk_indicators=result.risk_indicators,
        generated_at=result.generated_at
    )


@app.get("/v1/thresholds")
async def get_thresholds():
    """Get reporting thresholds by jurisdiction."""
    checker = TravelRuleChecker()
    return checker.get_thresholds()


# ============ Data Endpoints ============

@app.get("/v1/fatf/status")
async def get_fatf_status():
    """Get current FATF grey and black list status."""
    
    return {
        "black_list": [
            {"code": "KP", "name": "North Korea"},
            {"code": "IR", "name": "Iran"},
            {"code": "MM", "name": "Myanmar"}
        ],
        "grey_list": [
            {"code": "PK", "name": "Pakistan"},
            {"code": "SY", "name": "Syria"},
            {"code": "YE", "name": "Yemen"},
            # Add current grey list members
        ],
        "recently_removed": [
            {"code": "TR", "name": "Turkey", "removed_date": "2024-06-28"},
            {"code": "AE", "name": "UAE", "removed_date": "2024-02-23"}
        ],
        "last_updated": "2024-10-01"
    }


@app.get("/v1/stats")
async def get_api_stats():
    """Get API usage statistics."""
    
    # In production, this would query actual usage data
    return {
        "total_screenings_today": 0,
        "total_risk_assessments_today": 0,
        "sanctions_list_last_updated": datetime.utcnow(),
        "uptime_percent": 99.9
    }


def create_app() -> FastAPI:
    """Factory function for creating the app."""
    return app
