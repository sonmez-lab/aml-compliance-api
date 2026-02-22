"""Compliance services - SAR drafting and Travel Rule."""

from datetime import datetime
from decimal import Decimal
from typing import Optional
from dataclasses import dataclass, field
import structlog

from ..config import get_settings
from ..models import BlockchainType

logger = structlog.get_logger()


@dataclass
class SARDraftResult:
    """Generated SAR draft."""
    id: str
    narrative: str
    suspicious_activity_type: str
    
    # Subject
    subject_address: str
    subject_name: Optional[str] = None
    
    # Activity
    amount_involved: Decimal = Decimal(0)
    currency: str = "USD"
    activity_start_date: Optional[datetime] = None
    activity_end_date: Optional[datetime] = None
    
    # Risk indicators
    risk_indicators: list[str] = field(default_factory=list)
    
    # Transactions
    transactions: list[dict] = field(default_factory=list)
    
    generated_at: datetime = field(default_factory=datetime.utcnow)


class SARGenerator:
    """Generate Suspicious Activity Report drafts."""
    
    # SAR activity type codes
    ACTIVITY_TYPES = {
        "sanctions_evasion": "Structuring/Layering - Virtual Currency",
        "mixer_usage": "Use of Anonymization Services",
        "high_risk_jurisdiction": "Transactions with High-Risk Jurisdiction",
        "unusual_pattern": "Unusual Transaction Pattern",
        "rapid_movement": "Rapid Movement of Funds",
        "darknet": "Darknet Marketplace Connection",
        "ransomware": "Ransomware-Related Activity",
    }
    
    def __init__(self):
        self.settings = get_settings()
    
    async def generate_sar_draft(
        self,
        address: str,
        blockchain: BlockchainType,
        activity_type: str,
        transactions: list[dict] = None,
        additional_info: dict = None
    ) -> SARDraftResult:
        """Generate a SAR narrative draft."""
        
        transactions = transactions or []
        additional_info = additional_info or {}
        
        # Calculate totals
        total_amount = sum(Decimal(str(tx.get("amount_usd", 0))) for tx in transactions)
        
        # Determine date range
        dates = [tx.get("timestamp") for tx in transactions if tx.get("timestamp")]
        start_date = min(dates) if dates else None
        end_date = max(dates) if dates else None
        
        # Generate risk indicators
        risk_indicators = self._identify_risk_indicators(
            address, blockchain, activity_type, transactions
        )
        
        # Generate narrative
        narrative = self._generate_narrative(
            address=address,
            blockchain=blockchain,
            activity_type=activity_type,
            total_amount=total_amount,
            transactions=transactions,
            risk_indicators=risk_indicators,
            additional_info=additional_info
        )
        
        return SARDraftResult(
            id=f"SAR-DRAFT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            narrative=narrative,
            suspicious_activity_type=self.ACTIVITY_TYPES.get(activity_type, activity_type),
            subject_address=address,
            amount_involved=total_amount,
            currency="USD",
            activity_start_date=start_date,
            activity_end_date=end_date,
            risk_indicators=risk_indicators,
            transactions=transactions
        )
    
    def _identify_risk_indicators(
        self,
        address: str,
        blockchain: BlockchainType,
        activity_type: str,
        transactions: list[dict]
    ) -> list[str]:
        """Identify red flag indicators."""
        
        indicators = []
        
        # Activity type indicators
        if activity_type == "sanctions_evasion":
            indicators.append("Direct or indirect exposure to sanctioned entities")
        elif activity_type == "mixer_usage":
            indicators.append("Use of cryptocurrency mixing/tumbling services")
        elif activity_type == "high_risk_jurisdiction":
            indicators.append("Transactions linked to FATF grey/black list jurisdictions")
        
        # Transaction pattern indicators
        if transactions:
            # Check for structuring
            amounts = [tx.get("amount_usd", 0) for tx in transactions]
            if len(amounts) > 5 and all(a < 10000 for a in amounts):
                indicators.append("Possible structuring - multiple transactions below reporting threshold")
            
            # Check for rapid movement
            if len(transactions) > 10:
                indicators.append("High transaction velocity")
        
        return indicators
    
    def _generate_narrative(
        self,
        address: str,
        blockchain: BlockchainType,
        activity_type: str,
        total_amount: Decimal,
        transactions: list[dict],
        risk_indicators: list[str],
        additional_info: dict
    ) -> str:
        """Generate SAR narrative text."""
        
        tx_count = len(transactions)
        
        narrative = f"""SUSPICIOUS ACTIVITY REPORT - DRAFT

1. SUBJECT IDENTIFICATION
   Virtual Currency Address: {address}
   Blockchain: {blockchain.value.upper()}
   
2. SUSPICIOUS ACTIVITY SUMMARY
   Activity Type: {self.ACTIVITY_TYPES.get(activity_type, activity_type)}
   Total Amount Involved: ${total_amount:,.2f} USD (equivalent)
   Number of Transactions: {tx_count}
   
3. NARRATIVE
   The reporting institution identified suspicious activity involving the virtual 
   currency address {address} on the {blockchain.value.upper()} blockchain.
   
   During the review period, approximately ${total_amount:,.2f} USD equivalent was 
   transferred through this address across {tx_count} transaction(s).
   
"""
        
        # Add risk indicators
        if risk_indicators:
            narrative += "4. RED FLAG INDICATORS\n"
            for i, indicator in enumerate(risk_indicators, 1):
                narrative += f"   {i}. {indicator}\n"
            narrative += "\n"
        
        # Add activity type specific details
        if activity_type == "sanctions_evasion":
            narrative += """5. SANCTIONS NEXUS
   The address or its counterparties have been identified as having exposure to 
   OFAC-designated entities or addresses. This may indicate attempted evasion 
   of U.S. sanctions through virtual currency transactions.
   
"""
        elif activity_type == "mixer_usage":
            narrative += """5. MIXING SERVICE USAGE
   Analysis indicates the subject address has interacted with known cryptocurrency 
   mixing/tumbling services, which are commonly used to obscure the origin of funds 
   and break the transaction trail.
   
"""
        
        narrative += """6. RECOMMENDATION
   Based on the indicators identified, this activity warrants further investigation 
   and potential filing of a Suspicious Activity Report with FinCEN.
   
---
This is an AI-generated draft for compliance review purposes only.
Final SAR filing must be reviewed and approved by qualified compliance personnel.
"""
        
        return narrative


@dataclass
class TravelRuleResult:
    """Travel Rule compliance check result."""
    transaction_hash: Optional[str]
    blockchain: BlockchainType
    amount_usd: Decimal
    
    # Threshold
    threshold_usd: Decimal = Decimal("3000")
    threshold_exceeded: bool = False
    
    # Compliance
    travel_rule_required: bool = False
    is_compliant: bool = True
    
    # Missing information
    missing_originator_fields: list[str] = field(default_factory=list)
    missing_beneficiary_fields: list[str] = field(default_factory=list)
    
    # Status
    status: str = "compliant"  # compliant, missing_info, not_required


class TravelRuleChecker:
    """Check Travel Rule compliance for transactions."""
    
    # Required fields per FATF
    ORIGINATOR_REQUIRED = [
        "name",
        "account_number",  # or address
        "address",  # physical address
        "national_identifier",  # optional in some jurisdictions
    ]
    
    BENEFICIARY_REQUIRED = [
        "name",
        "account_number",  # or address
    ]
    
    # Threshold varies by jurisdiction
    THRESHOLDS = {
        "US": Decimal("3000"),
        "EU": Decimal("1000"),  # EUR
        "SG": Decimal("1500"),  # SGD
        "default": Decimal("1000"),
    }
    
    def __init__(self):
        self.settings = get_settings()
    
    def check_compliance(
        self,
        amount_usd: Decimal,
        blockchain: BlockchainType,
        originator_info: dict = None,
        beneficiary_info: dict = None,
        originator_jurisdiction: str = "US",
        beneficiary_jurisdiction: str = None,
        transaction_hash: str = None
    ) -> TravelRuleResult:
        """Check if transaction complies with Travel Rule."""
        
        originator_info = originator_info or {}
        beneficiary_info = beneficiary_info or {}
        
        # Get applicable threshold
        threshold = self.THRESHOLDS.get(originator_jurisdiction, self.THRESHOLDS["default"])
        threshold_exceeded = amount_usd >= threshold
        
        if not threshold_exceeded:
            return TravelRuleResult(
                transaction_hash=transaction_hash,
                blockchain=blockchain,
                amount_usd=amount_usd,
                threshold_usd=threshold,
                threshold_exceeded=False,
                travel_rule_required=False,
                is_compliant=True,
                status="not_required"
            )
        
        # Check required fields
        missing_originator = []
        for field in self.ORIGINATOR_REQUIRED:
            if field not in originator_info or not originator_info[field]:
                missing_originator.append(field)
        
        missing_beneficiary = []
        for field in self.BENEFICIARY_REQUIRED:
            if field not in beneficiary_info or not beneficiary_info[field]:
                missing_beneficiary.append(field)
        
        has_missing = len(missing_originator) > 0 or len(missing_beneficiary) > 0
        
        return TravelRuleResult(
            transaction_hash=transaction_hash,
            blockchain=blockchain,
            amount_usd=amount_usd,
            threshold_usd=threshold,
            threshold_exceeded=True,
            travel_rule_required=True,
            is_compliant=not has_missing,
            missing_originator_fields=missing_originator,
            missing_beneficiary_fields=missing_beneficiary,
            status="missing_info" if has_missing else "compliant"
        )
    
    def get_thresholds(self) -> dict:
        """Get Travel Rule thresholds by jurisdiction."""
        return {
            "US": {"threshold": 3000, "currency": "USD", "rule": "FinCEN Travel Rule"},
            "EU": {"threshold": 1000, "currency": "EUR", "rule": "TFR (Transfer of Funds Regulation)"},
            "SG": {"threshold": 1500, "currency": "SGD", "rule": "MAS Notice PSN02"},
            "JP": {"threshold": 100000, "currency": "JPY", "rule": "JFSA Travel Rule"},
            "KR": {"threshold": 1000000, "currency": "KRW", "rule": "FSC Travel Rule"},
        }
