#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B2B Compliance, KYB, Sanctions & Cyber Intelligence Python SDK (`b2b_compliance_sdk`)
Zero mandatory external dependencies (Python 3.11+ stdlib core + async support).
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__version__ = "1.0.0"

APIFY_OWNER = "b2b-quant-apis"
MASTER_MCP_ROUTER_SLUG = "b2b-quant-mcp-server"

RAPIDAPI_PUBLIC_SLUGS: set[str] = set([
    "b2b-gov-procurement-pncp-radar",
    "b2b-quant-mcp-server",
    "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
    "brazil-antt-freight-cte-auditor",
    "brazil-b2b-cnpj-qsa-lead-enricher",
    "brazil-bcb-ptax-sgs-financial-contract-indexer",
    "brazil-camara-legislative-regulatory-risk-radar",
    "brazil-cep-geocoordinates-logistics-auditor",
    "brazil-ibge-cnae-municipal-b2b-expansion-enricher",
    "brazil-pix-ispb-cvm-financial-kyb-auditor",
    "brazil-tax-reform-ncm-classtrib-auditor",
    "cisa-kev-ransomware-vulnerability-auditor",
    "eu-ted-public-tenders-procurement-radar",
    "eu-vies-vat-tax-compliance-auditor",
    "global-b2b-email-domain-security-auditor",
    "global-gleif-lei-corporate-ownership-kyb",
    "global-sanctions-pep-interpol-watchlist-screener",
    "healthcare-tiss-xml-validator",
    "icann-rdap-domain-whois-brand-recon",
    "multi-ats-tech-job-board-hiring-radar"
])
ALL_ENGINE_SLUGS: list[str] = [
    "b2b-gov-procurement-pncp-radar",
    "b2b-quant-mcp-server",
    "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
    "brazil-antt-freight-cte-auditor",
    "brazil-b2b-cnpj-qsa-lead-enricher",
    "brazil-bcb-ptax-sgs-financial-contract-indexer",
    "brazil-camara-legislative-regulatory-risk-radar",
    "brazil-cep-geocoordinates-logistics-auditor",
    "brazil-ibge-cnae-municipal-b2b-expansion-enricher",
    "brazil-pix-ispb-cvm-financial-kyb-auditor",
    "brazil-tax-reform-ncm-classtrib-auditor",
    "cisa-kev-ransomware-vulnerability-auditor",
    "eu-ted-public-tenders-procurement-radar",
    "eu-vies-vat-tax-compliance-auditor",
    "global-b2b-email-domain-security-auditor",
    "global-gleif-lei-corporate-ownership-kyb",
    "global-sanctions-pep-interpol-watchlist-screener",
    "healthcare-tiss-xml-validator",
    "icann-rdap-domain-whois-brand-recon",
    "multi-ats-tech-job-board-hiring-radar",
    "uk-fca-companies-house-kyb-compliance-auditor",
    "us-census-fcc-real-estate-geo-enricher",
    "us-clinical-trials-biotech-radar",
    "us-epa-echo-environmental-compliance-auditor",
    "us-fda-recalls-safety-monitor",
    "us-fdic-bankfind-institution-financial-auditor",
    "us-healthcare-npi-provider-lead-enricher",
    "us-nhtsa-vehicle-vin-recall-auditor",
    "us-osha-workplace-safety-violation-auditor",
    "us-sam-gov-federal-procurement-auditor",
    "us-sec-edgar-filings-insider-radar"
]


@dataclass(slots=True)
class AuditResult:
    engine: str
    provider: str
    status: str
    records: list[dict[str, Any]] = field(default_factory=list)
    upgrade_url: str = ""


class B2BComplianceClient:
    """Synchronous B2B Compliance & Cyber Intelligence SDK client."""

    def __init__(
        self,
        rapidapi_key: str | None = None,
        apify_token: str | None = None,
        zyla_api_key: str | None = None,
        timeout: float = 25.0,
        max_retries: int = 2,
    ) -> None:
        self.rapidapi_key = (rapidapi_key or os.environ.get("RAPIDAPI_API_KEY") or "").strip()
        self.apify_token = (apify_token or os.environ.get("APIFY_API_TOKEN") or "").strip()
        self.zyla_api_key = (zyla_api_key or os.environ.get("ZYLA_API_KEY") or "").strip()
        self.timeout = max(2.0, float(timeout))
        self.max_retries = max(1, int(max_retries))

    def _post_json(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> Any:
        req_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"b2b-compliance-sdk/{__version__} (+https://github.com/jesleytassili-glitch/b2b-compliance-python-sdk)",
            **headers,
        }
        data = json.dumps(payload).encode("utf-8")
        ctx = ssl.create_default_context()
        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(url=url, data=data, headers=req_headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw.strip() else []
            except Exception as exc:
                last_err = exc
                if attempt < self.max_retries:
                    time.sleep(0.5 * attempt)
        raise RuntimeError(f"B2BComplianceClient request failed ({url}): {last_err}")

    def run_engine(self, engine_slug: str, payload: dict[str, Any] | None = None) -> AuditResult:
        """Executes any of the 31 B2B compliance/cyber engines with smart RapidAPI/Apify/Preview routing."""
        slug = str(engine_slug or "").strip().lower()
        if slug not in ALL_ENGINE_SLUGS:
            raise ValueError(f"Unknown engine '{slug}'. Valid engines ({len(ALL_ENGINE_SLUGS)}): {ALL_ENGINE_SLUGS[:5]}...")
        safe_payload = dict(payload) if isinstance(payload, dict) else {}
        upgrade_link = (
            f"https://rapidapi.com/b2bquantapis/api/{slug}"
            if slug in RAPIDAPI_PUBLIC_SLUGS
            else f"https://apify.com/{APIFY_OWNER}/{slug}"
        )

        try:
            if self.rapidapi_key:
                if slug in RAPIDAPI_PUBLIC_SLUGS:
                    host = f"{slug}.p.rapidapi.com"
                    url = f"https://{host}/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
                    raw = self._post_json(url, {"X-RapidAPI-Key": self.rapidapi_key, "X-RapidAPI-Host": host}, safe_payload)
                else:
                    # Transparently routes the 11 remaining engines via the PUBLIC Master MCP Router on RapidAPI
                    host = f"{MASTER_MCP_ROUTER_SLUG}.p.rapidapi.com"
                    url = f"https://{host}/v2/acts/{APIFY_OWNER}~{MASTER_MCP_ROUTER_SLUG}/run-sync-get-dataset-items"
                    router_payload = {
                        "operationMode": "invoke_tool",
                        "toolName": slug,
                        "toolArguments": safe_payload,
                    }
                    raw = self._post_json(url, {"X-RapidAPI-Key": self.rapidapi_key, "X-RapidAPI-Host": host}, router_payload)
                records = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
                return AuditResult(engine=slug, provider="rapidapi", status="completed_cloud", records=records, upgrade_url=upgrade_link)

            if self.apify_token:
                url = f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
                raw = self._post_json(url, {"Authorization": f"Bearer {self.apify_token}"}, safe_payload)
                records = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
                return AuditResult(engine=slug, provider="apify", status="completed_cloud", records=records, upgrade_url=upgrade_link)
        except Exception as err:
            return AuditResult(
                engine=slug,
                provider="zero-key-preview-fallback",
                status="fallback_preview",
                records=[{"engine": slug, "preview": True, "fallbackReason": str(err), "inputEcho": safe_payload, "upgradeUrl": upgrade_link}],
                upgrade_url=upgrade_link,
            )

        return AuditResult(
            engine=slug,
            provider="zero-key-preview",
            status="completed_preview",
            records=[{
                "engine": slug,
                "preview": True,
                "inputEcho": safe_payload,
                "message": "Set RAPIDAPI_API_KEY (BASIC Free 15/mo or PRO $19/mo) or APIFY_API_TOKEN for live cloud datasets.",
                "upgradeUrl": upgrade_link,
            }],
            upgrade_url=upgrade_link,
        )

    def screen_sanctions(self, entities: list[str], fuzzy_threshold: float = 0.82) -> AuditResult:
        return self.run_engine("global-sanctions-pep-interpol-watchlist-screener", {"entities": entities, "fuzzyThreshold": fuzzy_threshold})

    def audit_cisa_kev(self, cve_ids: list[str]) -> AuditResult:
        return self.run_engine("cisa-kev-ransomware-vulnerability-auditor", {"cveIds": cve_ids})

    def verify_eu_vat(self, vat_numbers: list[str]) -> AuditResult:
        return self.run_engine("eu-vies-vat-tax-compliance-auditor", {"vatNumbers": vat_numbers})

    def enrich_gleif_lei(self, queries: list[str]) -> AuditResult:
        return self.run_engine("global-gleif-lei-corporate-ownership-kyb", {"queries": queries})

    def scan_ssl_attack_surface(self, domains: list[str], max_subdomains: int = 25) -> AuditResult:
        return self.run_engine("b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor", {"domains": domains, "maxSubdomains": max_subdomains})

    def audit_brazil_cnpj(self, cnpjs: list[str]) -> AuditResult:
        return self.run_engine("brazil-b2b-cnpj-qsa-lead-enricher", {"cnpjs": cnpjs})

    def search_sec_edgar(self, tickers: list[str]) -> AuditResult:
        return self.run_engine("us-sec-edgar-filings-insider-radar", {"tickers": tickers})


class AsyncB2BComplianceClient:
    """Async wrapper running B2BComplianceClient safely via asyncio.to_thread."""

    def __init__(self, **kwargs: Any) -> None:
        self._sync = B2BComplianceClient(**kwargs)

    async def run_engine(self, engine_slug: str, payload: dict[str, Any] | None = None) -> AuditResult:
        return await asyncio.to_thread(self._sync.run_engine, engine_slug, payload)
