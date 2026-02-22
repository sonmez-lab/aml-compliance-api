#!/usr/bin/env python3
"""
AML Compliance API - CLI Entry Point

Unified REST API for cryptocurrency AML/sanctions compliance.

Usage:
    python main.py serve        # Start API server
    python main.py screen <addr> # Screen address
    python main.py risk <addr>  # Risk assessment
    python main.py refresh      # Refresh sanctions cache
"""

import asyncio
import argparse
import sys
from datetime import datetime

import structlog
import uvicorn

from src.config import get_settings, TIER_LIMITS
from src.services import get_screener, RiskAssessor, TravelRuleChecker
from src.models import BlockchainType

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()


async def cmd_serve(args):
    """Start the API server."""
    settings = get_settings()
    
    logger.info(
        "Starting AML Compliance API",
        host=settings.host,
        port=settings.port
    )
    
    config = uvicorn.Config(
        "src.api:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info"
    )
    server = uvicorn.Server(config)
    await server.serve()


async def cmd_screen(args):
    """Screen an address against sanctions lists."""
    
    try:
        blockchain = BlockchainType(args.blockchain)
    except ValueError:
        print(f"Error: Invalid blockchain '{args.blockchain}'")
        sys.exit(1)
    
    screener = get_screener()
    
    try:
        print(f"\nScreening: {args.address}")
        print(f"Blockchain: {blockchain.value}")
        print("=" * 60)
        
        result = await screener.screen_address(args.address, blockchain)
        
        status_icon = "🚨" if result.is_sanctioned else "✅"
        print(f"\n{status_icon} Sanctioned: {result.is_sanctioned}")
        print(f"📊 Risk Level: {result.risk_level.value.upper()}")
        print(f"📈 Risk Score: {result.risk_score}/100")
        print(f"⏱️  Response Time: {result.response_time_ms}ms")
        
        if result.matches:
            print(f"\n🔍 Matches Found:")
            for match in result.matches:
                print(f"   • Source: {match.get('source')}")
                print(f"     Entity: {match.get('entity_name')}")
                print(f"     Program: {match.get('program')}")
        
        print(f"\n📋 Sources Checked: {', '.join(result.sources_checked)}")
        
    finally:
        await screener.close()


async def cmd_risk(args):
    """Perform risk assessment on an address."""
    
    try:
        blockchain = BlockchainType(args.blockchain)
    except ValueError:
        print(f"Error: Invalid blockchain '{args.blockchain}'")
        sys.exit(1)
    
    assessor = RiskAssessor()
    screener = get_screener()
    
    try:
        print(f"\nRisk Assessment: {args.address}")
        print(f"Blockchain: {blockchain.value}")
        print("=" * 60)
        
        result = await assessor.assess_address(args.address, blockchain)
        
        # Risk level colors
        level_icons = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
            "prohibited": "⛔"
        }
        
        icon = level_icons.get(result.risk_level.value, "⚪")
        
        print(f"\n{icon} Overall Risk Level: {result.risk_level.value.upper()}")
        print(f"📊 Overall Score: {result.risk_score}/100")
        
        print(f"\n📈 Category Breakdown:")
        print(f"   Sanctions:    {result.sanctions_score}/100")
        print(f"   Jurisdiction: {result.jurisdiction_score}/100")
        print(f"   Behavior:     {result.behavior_score}/100")
        print(f"   Counterparty: {result.counterparty_score}/100")
        
        if result.factors:
            print(f"\n🔍 Risk Factors:")
            for factor in result.factors:
                severity_icon = {"low": "◦", "medium": "•", "high": "◉", "critical": "⬤"}
                print(f"   {severity_icon.get(factor.severity, '○')} [{factor.category}] {factor.name}")
        
        if result.recommendations:
            print(f"\n💡 Recommendations:")
            for rec in result.recommendations:
                print(f"   → {rec}")
        
    finally:
        await screener.close()


async def cmd_refresh(args):
    """Refresh sanctions cache from all sources."""
    
    screener = get_screener()
    
    try:
        print("Refreshing sanctions cache...")
        await screener.refresh_sanctions_cache()
        print("✅ Sanctions cache refreshed successfully")
    except Exception as e:
        print(f"❌ Error refreshing cache: {e}")
    finally:
        await screener.close()


async def cmd_pricing(args):
    """Show pricing tiers."""
    
    print("\n" + "=" * 60)
    print("AML Compliance API - Pricing Tiers")
    print("=" * 60)
    
    for tier, limits in TIER_LIMITS.items():
        print(f"\n📦 {tier.value.upper()}")
        print(f"   Price: ${limits['price_monthly']}/month" if isinstance(limits['price_monthly'], int) else f"   Price: {limits['price_monthly']}")
        print(f"   Daily Calls: {limits['daily_calls'] if limits['daily_calls'] > 0 else 'Unlimited'}")
        print(f"   Batch Size: {limits['batch_size']}")
        print(f"   Features: {', '.join(limits['features'])}")


def main():
    parser = argparse.ArgumentParser(
        description="AML Compliance API CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # serve
    subparsers.add_parser("serve", help="Start API server")
    
    # screen
    screen_parser = subparsers.add_parser("screen", help="Screen address")
    screen_parser.add_argument("address", help="Address to screen")
    screen_parser.add_argument("--blockchain", "-b", default="ethereum")
    
    # risk
    risk_parser = subparsers.add_parser("risk", help="Risk assessment")
    risk_parser.add_argument("address", help="Address to assess")
    risk_parser.add_argument("--blockchain", "-b", default="ethereum")
    
    # refresh
    subparsers.add_parser("refresh", help="Refresh sanctions cache")
    
    # pricing
    subparsers.add_parser("pricing", help="Show pricing tiers")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    commands = {
        "serve": cmd_serve,
        "screen": cmd_screen,
        "risk": cmd_risk,
        "refresh": cmd_refresh,
        "pricing": cmd_pricing
    }
    
    asyncio.run(commands[args.command](args))


if __name__ == "__main__":
    main()
