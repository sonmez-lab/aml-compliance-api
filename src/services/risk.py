"""Risk assessment service."""

from datetime import datetime
from decimal import Decimal
from typing import Optional
from dataclasses import dataclass, field
import structlog

from ..config import get_settings
from ..models import RiskLevel, BlockchainType

logger = structlog.get_logger()


@dataclass
class RiskFactor:
    """Individual risk factor."""
    name: str
    category: str  # sanctions, jurisdiction, behavior, counterparty
    score: float   # 0-100
    weight: float  # Weight in overall score
    description: str
    severity: str  # low, medium, high, critical


@dataclass
class RiskAssessmentResult:
    """Comprehensive risk assessment result."""
    address: str
    blockchain: BlockchainType
    
    # Overall
    risk_score: float  # 0-100
    risk_level: RiskLevel
    
    # Category scores
    sanctions_score: float = 0.0
    jurisdiction_score: float = 0.0
    behavior_score: float = 0.0
    counterparty_score: float = 0.0
    
    # Factors
    factors: list[RiskFactor] = field(default_factory=list)
    
    # Recommendations
    recommendations: list[str] = field(default_factory=list)
    
    assessed_at: datetime = field(default_factory=datetime.utcnow)


class RiskAssessor:
    """Multi-factor risk assessment engine."""
    
    # Category weights
    WEIGHTS = {
        "sanctions": 0.40,
        "jurisdiction": 0.25,
        "behavior": 0.20,
        "counterparty": 0.15
    }
    
    def __init__(self):
        self.settings = get_settings()
    
    async def assess_address(
        self,
        address: str,
        blockchain: BlockchainType = BlockchainType.ETHEREUM,
        include_behavior: bool = True,
        include_counterparty: bool = True
    ) -> RiskAssessmentResult:
        """Perform comprehensive risk assessment."""
        
        factors = []
        
        # 1. Sanctions Check
        sanctions_score, sanctions_factors = await self._assess_sanctions(address)
        factors.extend(sanctions_factors)
        
        # 2. Jurisdiction Risk
        jurisdiction_score, jurisdiction_factors = await self._assess_jurisdiction(address, blockchain)
        factors.extend(jurisdiction_factors)
        
        # 3. Behavioral Analysis (optional, requires more data)
        behavior_score = 0.0
        if include_behavior:
            behavior_score, behavior_factors = await self._assess_behavior(address, blockchain)
            factors.extend(behavior_factors)
        
        # 4. Counterparty Risk (optional)
        counterparty_score = 0.0
        if include_counterparty:
            counterparty_score, counterparty_factors = await self._assess_counterparty(address, blockchain)
            factors.extend(counterparty_factors)
        
        # Calculate weighted overall score
        overall_score = (
            sanctions_score * self.WEIGHTS["sanctions"] +
            jurisdiction_score * self.WEIGHTS["jurisdiction"] +
            behavior_score * self.WEIGHTS["behavior"] +
            counterparty_score * self.WEIGHTS["counterparty"]
        )
        
        risk_level = self._score_to_level(overall_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(factors, risk_level)
        
        return RiskAssessmentResult(
            address=address,
            blockchain=blockchain,
            risk_score=round(overall_score, 2),
            risk_level=risk_level,
            sanctions_score=round(sanctions_score, 2),
            jurisdiction_score=round(jurisdiction_score, 2),
            behavior_score=round(behavior_score, 2),
            counterparty_score=round(counterparty_score, 2),
            factors=factors,
            recommendations=recommendations
        )
    
    async def _assess_sanctions(self, address: str) -> tuple[float, list[RiskFactor]]:
        """Assess sanctions-related risk."""
        
        from .screening import get_screener
        
        screener = get_screener()
        result = await screener.screen_address(address)
        
        factors = []
        
        if result.is_sanctioned:
            factors.append(RiskFactor(
                name="Direct Sanctions Match",
                category="sanctions",
                score=100.0,
                weight=1.0,
                description=f"Address matches OFAC/sanctions list",
                severity="critical"
            ))
            return 100.0, factors
        
        # Check for indirect sanctions exposure
        # This would query blockchain analytics for exposure to sanctioned entities
        indirect_score = 10.0  # Baseline
        
        factors.append(RiskFactor(
            name="No Direct Sanctions",
            category="sanctions",
            score=indirect_score,
            weight=1.0,
            description="No direct sanctions matches found",
            severity="low"
        ))
        
        return indirect_score, factors
    
    async def _assess_jurisdiction(
        self, 
        address: str, 
        blockchain: BlockchainType
    ) -> tuple[float, list[RiskFactor]]:
        """Assess jurisdiction-related risk."""
        
        factors = []
        
        # In production, this would:
        # 1. Determine associated jurisdictions from blockchain data
        # 2. Check FATF status of those jurisdictions
        # 3. Calculate weighted jurisdiction risk
        
        # For now, return baseline
        base_score = 20.0
        
        factors.append(RiskFactor(
            name="Jurisdiction Analysis",
            category="jurisdiction",
            score=base_score,
            weight=1.0,
            description="Standard jurisdiction risk profile",
            severity="low"
        ))
        
        return base_score, factors
    
    async def _assess_behavior(
        self, 
        address: str, 
        blockchain: BlockchainType
    ) -> tuple[float, list[RiskFactor]]:
        """Assess behavioral risk patterns."""
        
        factors = []
        
        # This would analyze:
        # - Transaction patterns (velocity, amounts)
        # - Mixer/tumbler usage
        # - Exchange patterns
        # - Time-based patterns
        
        behavior_indicators = [
            # Example indicators
            {"name": "Transaction Velocity", "score": 15, "severity": "low"},
            {"name": "Amount Patterns", "score": 10, "severity": "low"},
        ]
        
        total_score = 0.0
        for indicator in behavior_indicators:
            factors.append(RiskFactor(
                name=indicator["name"],
                category="behavior",
                score=indicator["score"],
                weight=1.0 / len(behavior_indicators),
                description=f"Behavioral indicator: {indicator['name']}",
                severity=indicator["severity"]
            ))
            total_score += indicator["score"]
        
        avg_score = total_score / len(behavior_indicators) if behavior_indicators else 0
        
        return avg_score, factors
    
    async def _assess_counterparty(
        self, 
        address: str, 
        blockchain: BlockchainType
    ) -> tuple[float, list[RiskFactor]]:
        """Assess counterparty exposure risk."""
        
        factors = []
        
        # This would analyze:
        # - Direct counterparty risk
        # - Hop analysis (exposure via intermediaries)
        # - Exchange/service counterparties
        
        base_score = 15.0
        
        factors.append(RiskFactor(
            name="Counterparty Exposure",
            category="counterparty",
            score=base_score,
            weight=1.0,
            description="Standard counterparty risk profile",
            severity="low"
        ))
        
        return base_score, factors
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert score to risk level."""
        if score >= 90:
            return RiskLevel.PROHIBITED
        elif score >= 70:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 30:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_recommendations(
        self, 
        factors: list[RiskFactor], 
        risk_level: RiskLevel
    ) -> list[str]:
        """Generate actionable recommendations based on risk factors."""
        
        recommendations = []
        
        if risk_level == RiskLevel.PROHIBITED:
            recommendations.append("BLOCK TRANSACTION: Address is on sanctions list")
            recommendations.append("File SAR immediately")
            recommendations.append("Document all interactions")
            return recommendations
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append("Enhanced due diligence required")
            recommendations.append("Senior compliance review before proceeding")
            recommendations.append("Consider SAR filing")
        
        if risk_level == RiskLevel.HIGH:
            recommendations.append("Additional verification recommended")
            recommendations.append("Monitor future transactions")
        
        if risk_level == RiskLevel.MEDIUM:
            recommendations.append("Standard monitoring")
        
        if risk_level == RiskLevel.LOW:
            recommendations.append("Standard processing acceptable")
        
        # Add factor-specific recommendations
        for factor in factors:
            if factor.severity == "critical":
                recommendations.append(f"Address {factor.name}: {factor.description}")
        
        return recommendations


async def get_jurisdiction_risk(country_code: str) -> dict:
    """Get risk profile for a jurisdiction."""
    
    # FATF status data (simplified - in production, use database)
    fatf_data = {
        # Black list
        "KP": {"status": "black_list", "risk_score": 100, "name": "North Korea"},
        "IR": {"status": "black_list", "risk_score": 95, "name": "Iran"},
        "MM": {"status": "black_list", "risk_score": 90, "name": "Myanmar"},
        
        # Grey list (examples)
        "PK": {"status": "grey_list", "risk_score": 70, "name": "Pakistan"},
        "SY": {"status": "grey_list", "risk_score": 75, "name": "Syria"},
        "YE": {"status": "grey_list", "risk_score": 72, "name": "Yemen"},
        
        # Recently removed from grey list
        "TR": {"status": "compliant", "risk_score": 45, "name": "Turkey"},
        "AE": {"status": "compliant", "risk_score": 40, "name": "UAE"},
        
        # Standard
        "US": {"status": "compliant", "risk_score": 20, "name": "United States"},
        "GB": {"status": "compliant", "risk_score": 18, "name": "United Kingdom"},
        "DE": {"status": "compliant", "risk_score": 15, "name": "Germany"},
        "JP": {"status": "compliant", "risk_score": 12, "name": "Japan"},
        "SG": {"status": "compliant", "risk_score": 15, "name": "Singapore"},
    }
    
    return fatf_data.get(country_code.upper(), {
        "status": "unknown",
        "risk_score": 50,
        "name": country_code
    })
