"""Sanctions screening service."""

import asyncio
from datetime import datetime
from decimal import Decimal
from typing import Optional
import httpx
import structlog
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET

from ..config import get_settings
from ..models import SanctionsSource, BlockchainType, RiskLevel

logger = structlog.get_logger()


@dataclass
class ScreeningResult:
    """Result of a sanctions screening."""
    address: str
    blockchain: BlockchainType
    is_sanctioned: bool
    risk_level: RiskLevel
    risk_score: float  # 0-100
    
    # Matches found
    matches: list[dict] = field(default_factory=list)
    
    # Sources checked
    sources_checked: list[str] = field(default_factory=list)
    
    # Timing
    screened_at: datetime = field(default_factory=datetime.utcnow)
    response_time_ms: int = 0


class SanctionsScreener:
    """Screen addresses against multiple sanctions lists."""
    
    # Known sanctioned address patterns (for demo - in production, use DB)
    OFAC_CRYPTO_ID_TYPES = [
        "Digital Currency Address - XBT",
        "Digital Currency Address - ETH",
        "Digital Currency Address - USDT",
        "Digital Currency Address - TRX"
    ]
    
    def __init__(self):
        self.settings = get_settings()
        self.client = httpx.AsyncClient(timeout=30.0)
        
        # In-memory cache (in production, use Redis)
        self._sanctions_cache: dict[str, dict] = {}
        self._last_update: Optional[datetime] = None
    
    async def screen_address(
        self, 
        address: str, 
        blockchain: BlockchainType = BlockchainType.ETHEREUM
    ) -> ScreeningResult:
        """Screen a single address against all sanctions lists."""
        
        start_time = datetime.utcnow()
        
        # Normalize address
        address = address.lower().strip()
        
        # Check cache first
        if address in self._sanctions_cache:
            cached = self._sanctions_cache[address]
            return ScreeningResult(
                address=address,
                blockchain=blockchain,
                is_sanctioned=True,
                risk_level=RiskLevel.PROHIBITED,
                risk_score=100.0,
                matches=[cached],
                sources_checked=["cache"],
                response_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
        
        # Check OFAC
        ofac_match = await self._check_ofac(address)
        
        # Check other sources in parallel
        # eu_match, uk_match = await asyncio.gather(
        #     self._check_eu(address),
        #     self._check_uk(address)
        # )
        
        matches = []
        if ofac_match:
            matches.append(ofac_match)
        
        is_sanctioned = len(matches) > 0
        
        # Calculate risk
        if is_sanctioned:
            risk_level = RiskLevel.PROHIBITED
            risk_score = 100.0
        else:
            # Even if not sanctioned, check for indirect risk
            risk_score = await self._calculate_indirect_risk(address, blockchain)
            risk_level = self._score_to_level(risk_score)
        
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ScreeningResult(
            address=address,
            blockchain=blockchain,
            is_sanctioned=is_sanctioned,
            risk_level=risk_level,
            risk_score=risk_score,
            matches=matches,
            sources_checked=["ofac"],
            response_time_ms=response_time
        )
    
    async def batch_screen(
        self, 
        addresses: list[dict],
        max_concurrent: int = 10
    ) -> list[ScreeningResult]:
        """Screen multiple addresses concurrently."""
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def screen_with_semaphore(addr_info: dict) -> ScreeningResult:
            async with semaphore:
                return await self.screen_address(
                    addr_info["address"],
                    BlockchainType(addr_info.get("blockchain", "ethereum"))
                )
        
        tasks = [screen_with_semaphore(addr) for addr in addresses]
        results = await asyncio.gather(*tasks)
        
        return results
    
    async def _check_ofac(self, address: str) -> Optional[dict]:
        """Check address against OFAC SDN list."""
        
        # In production, this would query a database or Redis cache
        # that's populated by a background job fetching OFAC data
        
        # For now, check against known addresses (demo)
        known_ofac_addresses = [
            # Example sanctioned addresses (use actual OFAC data in production)
            "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c",  # Tornado Cash
            "0x722122df12d4e14e13ac3b6895a86e84145b6967",
            "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        ]
        
        if address.lower() in [a.lower() for a in known_ofac_addresses]:
            return {
                "source": "OFAC",
                "sdn_id": "EXAMPLE",
                "entity_name": "Sanctioned Entity",
                "program": "CYBER2",
                "designation_date": "2022-08-08"
            }
        
        return None
    
    async def _calculate_indirect_risk(
        self, 
        address: str, 
        blockchain: BlockchainType
    ) -> float:
        """Calculate risk from indirect factors (counterparty exposure, etc.)."""
        
        # This would integrate with blockchain analytics APIs
        # For now, return low risk for unknown addresses
        return 10.0
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
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
    
    async def refresh_sanctions_cache(self):
        """Refresh the sanctions cache from all sources."""
        logger.info("Refreshing sanctions cache...")
        
        try:
            # Fetch OFAC SDN list
            response = await self.client.get(self.settings.ofac_sdn_url)
            response.raise_for_status()
            
            # Parse and extract crypto addresses
            root = ET.fromstring(response.text)
            ns = {"sdn": "http://www.un.org/sanctions/1.0"}
            
            count = 0
            for entry in root.findall(".//sdnEntry", ns):
                id_list = entry.find("idList", ns)
                if id_list is None:
                    continue
                
                for id_entry in id_list.findall("id", ns):
                    id_type = id_entry.find("idType", ns)
                    id_number = id_entry.find("idNumber", ns)
                    
                    if id_type is not None and id_type.text in self.OFAC_CRYPTO_ID_TYPES:
                        addr = id_number.text.lower() if id_number is not None else ""
                        if addr:
                            uid = entry.find("uid", ns)
                            name = entry.find("lastName", ns) or entry.find("firstName", ns)
                            
                            self._sanctions_cache[addr] = {
                                "source": "OFAC",
                                "sdn_id": uid.text if uid is not None else "",
                                "entity_name": name.text if name is not None else "",
                                "designation_date": datetime.utcnow().isoformat()
                            }
                            count += 1
            
            self._last_update = datetime.utcnow()
            logger.info(f"Sanctions cache refreshed: {count} crypto addresses")
            
        except Exception as e:
            logger.error(f"Failed to refresh sanctions cache: {e}")
    
    async def search_sanctions(
        self,
        query: str,
        source: Optional[SanctionsSource] = None,
        limit: int = 50
    ) -> list[dict]:
        """Search sanctions lists by name or address."""
        
        results = []
        query_lower = query.lower()
        
        for addr, data in self._sanctions_cache.items():
            if query_lower in addr or query_lower in data.get("entity_name", "").lower():
                if source is None or data.get("source") == source.value.upper():
                    results.append({
                        "address": addr,
                        **data
                    })
                    
                    if len(results) >= limit:
                        break
        
        return results
    
    async def close(self):
        await self.client.aclose()


# Singleton instance
_screener: Optional[SanctionsScreener] = None


def get_screener() -> SanctionsScreener:
    """Get the screener singleton."""
    global _screener
    if _screener is None:
        _screener = SanctionsScreener()
    return _screener
