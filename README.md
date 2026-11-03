# 🐍 `b2b-compliance-sdk` — Official Python SDK (31 B2B Compliance, KYB & Cyber Engines)

[![PyPI](https://img.shields.io/pypi/v/b2b-compliance-sdk?color=brightgreen&label=PyPI)](https://pypi.org/project/b2b-compliance-sdk/)
[![Release](https://img.shields.io/github/v/release/jesleytassili-glitch/b2b-compliance-python-sdk?color=brightgreen&label=Wheel%20Release)](https://github.com/jesleytassili-glitch/b2b-compliance-python-sdk/releases/tag/v1.0.0)
[![Official MCP Registry](https://img.shields.io/badge/Official_MCP_Registry-7%2F7_Live-6366F1)](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.jesleytassili-glitch)
[![RapidAPI Hub](https://img.shields.io/badge/RapidAPI-@b2bquantapis-0055FF)](https://rapidapi.com/user/b2bquantapis)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Zero-dependency typed Python SDK (`sync` + `async`) covering **31 stateless B2B regulatory, KYB, OFAC sanctions, EU VAT, GLEIF LEI, SEC EDGAR, CISA KEV CVE, SSL CT Log, and Brazil Tax/CNPJ engines**.

## ⚡ Instant Install (`pip` / `uv`)

```bash
pip install b2b-compliance-sdk
```

## 🚀 Usage Example

```python
from b2b_compliance_sdk import B2BComplianceClient

# Works immediately in Zero-Key Preview, or pass rapidapi_key / apify_token for live cloud data
client = B2BComplianceClient(rapidapi_key="YOUR_RAPIDAPI_KEY")

sanctions = client.screen_sanctions(["Acme Global Trading Ltd", "Siemens AG"])
kev = client.audit_cisa_kev(["CVE-2024-3094"])
vat = client.verify_eu_vat(["IE6388047V"])
print(sanctions.status, sanctions.records)
```

## 🔑 Get an API Key
- **RapidAPI Hub (`BASIC $0/15 req` • `PRO $19/mo` • `ULTRA $49/mo`):** https://rapidapi.com/user/b2bquantapis
- **Apify Store (`Pay-Per-Event`):** https://apify.com/b2b-quant-apis
