# AML Compliance API

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)

**Unified REST API for cryptocurrency AML/sanctions compliance, integrating screening, risk scoring, and regulatory reporting.**

## 🎯 Purpose

This API serves as the integration layer for all compliance tools, providing a single interface for:

- Wallet address sanctions screening
- Multi-factor risk scoring
- Jurisdiction compliance checks
- SAR draft generation
- Travel Rule compliance

## 🔗 API Endpoints

### Screening
```
POST /v1/screen          - Screen wallet address
POST /v1/batch-screen    - Batch screening
GET  /v1/sanctions       - Search sanctions lists
```

### Risk Assessment
```
POST /v1/risk-score      - Calculate risk score
GET  /v1/jurisdiction    - Jurisdiction risk profile
POST /v1/transaction     - Transaction risk analysis
```

### Compliance
```
POST /v1/travel-rule     - Travel Rule compliance check
POST /v1/sar-draft       - Generate SAR narrative draft
GET  /v1/thresholds      - Get reporting thresholds
```

### Data
```
GET  /v1/fatf/status     - FATF country status
GET  /v1/ofac/addresses  - OFAC crypto addresses
GET  /v1/stats           - API usage statistics
```

## 💰 Pricing Model (SaaS)

| Tier | Price | API Calls | Features |
|------|-------|-----------|----------|
| Free | $0 | 100/day | Basic screening |
| Starter | $99/mo | 10K/day | + Risk scores |
| Pro | $499/mo | Unlimited | + Monitoring, SAR |
| Enterprise | Custom | Custom | + SLA, Support |

## 🛠️ Tech Stack

- FastAPI (async, auto OpenAPI docs)
- PostgreSQL + Redis
- Celery for async monitoring
- JWT authentication
- Docker deployment

## 👤 Author

**Osman Sönmez**

Blockchain Security Researcher & Legal Tech Specialist | Smart Contract Auditor | Solidity Developer

Bridging the gap between legal compliance and blockchain technology. Specializing in cryptocurrency AML/CFT frameworks, smart contract security audits, and regulatory technology solutions.

- 🌐 Website: [osmansonmez.com](https://osmansonmez.com)
- 💼 LinkedIn: [linkedin.com/in/sonmezosman](https://www.linkedin.com/in/sonmezosman)
- 🔐 Focus: Blockchain Security | AML Compliance | Smart Contract Auditing

---

## 📄 License

MIT License
