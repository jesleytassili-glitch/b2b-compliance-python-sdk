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

__version__ = "1.0.2"

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
ZYLA_ENDPOINTS: dict[str, str] = {
    "b2b-gov-procurement-pncp-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37723/run+b2b+gov+procurement+pncp+radar",
    "us-sam-gov-federal-procurement-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37728/run+us+sam+gov+federal+procurement+auditor",
    "eu-ted-public-tenders-procurement-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37729/run+eu+ted+public+tenders+procurement+radar",
    "brazil-camara-legislative-regulatory-risk-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37730/run+brazil+camara+legislative+regulatory+risk",
    "us-osha-workplace-safety-violation-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37731/run+us+osha+workplace+safety+violation+auditor",
    "us-epa-echo-environmental-compliance-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37732/run+us+epa+echo+environmental+compliance",
    "brazil-tax-reform-ncm-classtrib-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37724/run+brazil+tax+reform+ncm+classtrib+auditor",
    "eu-vies-vat-tax-compliance-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37775/run+eu+vies+vat+tax+compliance+auditor",
    "us-sec-edgar-filings-insider-radar": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37776/run+us+sec+edgar+filings+insider+radar",
    "us-fdic-bankfind-institution-financial-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37777/run+us+fdic+bankfind+institution+financial",
    "global-gleif-lei-corporate-ownership-kyb": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37778/run+global+gleif+lei+corporate+ownership+kyb",
    "brazil-bcb-ptax-sgs-financial-contract-indexer": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37779/run+brazil+bcb+ptax+sgs+financial+contract+indexer",
    "brazil-pix-ispb-cvm-financial-kyb-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37780/run+brazil+pix+ispb+cvm+financial+kyb+auditor",
    "uk-fca-companies-house-kyb-compliance-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37781/run+uk+fca+companies+house+kyb+compliance",
    "healthcare-tiss-xml-validator": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37725/run+healthcare+tiss+xml+validator",
    "us-healthcare-npi-provider-lead-enricher": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37838/run+us+healthcare+npi+provider+lead+enricher",
    "us-clinical-trials-biotech-radar": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37839/run+us+clinical+trials+biotech+radar",
    "brazil-antt-freight-cte-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37726/run+brazil+antt+minimum+freight+calculator+ct+e",
    "brazil-cep-geocoordinates-logistics-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37846/run+brazil+cep+geocoordinates+ibge+code+api",
    "us-nhtsa-vehicle-vin-recall-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37847/run+us+nhtsa+vehicle+vin+decoder+safety+recall+a",
    "us-census-fcc-real-estate-geo-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37848/run+us+real+estate+census+tract+fips+proptech+ap",
    "brazil-b2b-cnpj-qsa-lead-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37849/run+brazil+b2b+cnpj+partners+qsa+cnae+lead+api",
    "brazil-ibge-cnae-municipal-b2b-expansion-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37850/run+brazil+ibge+cnae+2+3+municipal+code+b2b+tax",
    "multi-ats-tech-job-board-hiring-radar": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37851/run+multi+ats+tech+job+board+b2b+hiring+intent+a",
    "us-fda-recalls-safety-monitor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37727/run+us+fda+recalls+safety+monitor+food+drug+api",
    "cisa-kev-ransomware-vulnerability-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37866/run+us+cisa+kev+exploited+vulnerabilities+api",
    "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37867/run+b2b+ssl+tls+ct+log+subdomain+attack+surface",
    "global-b2b-email-domain-security-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37868/run+global+b2b+email+mx+spf+dmarc+deliverability",
    "icann-rdap-domain-whois-brand-recon": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37869/run+icann+rdap+official+domain+whois+brand+api",
    "global-sanctions-pep-interpol-watchlist-screener": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37870/run+global+ofac+un+eu+sanctions+pep+watchlist+ap",
    "b2b-quant-mcp-server": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37871/run+b2b+regulatory+kyb+fintech+secops+mcp+server"
}


def _unwrap_mcp_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list) and len(raw) == 1 and isinstance(raw[0], dict) and "mcpJsonRpcEnvelope" in raw[0]:
        env = raw[0].get("mcpJsonRpcEnvelope") or {}
        live = (env.get("result") or {}).get("liveDatasetItems")
        if isinstance(live, list):
            return [r for r in live if isinstance(r, dict)]
    if isinstance(raw, dict) and "mcpJsonRpcEnvelope" in raw:
        live = ((raw.get("mcpJsonRpcEnvelope") or {}).get("result") or {}).get("liveDatasetItems")
        if isinstance(live, list):
            return [r for r in live if isinstance(r, dict)]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        items = raw.get("items") or raw.get("data") or raw.get("results")
        return list(items) if isinstance(items, list) else [raw]
    return []


def _to_str_list(val: list[str] | str) -> list[str]:
    if isinstance(val, str):
        return [x.strip() for x in val.split(",") if x.strip()]
    return [str(x).strip() for x in (val or []) if str(x).strip()]


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
        self.rapidapi_key = (rapidapi_key if rapidapi_key is not None else os.environ.get("RAPIDAPI_API_KEY") or "").strip()
        self.apify_token = (apify_token if apify_token is not None else os.environ.get("APIFY_API_TOKEN") or "").strip()
        self.zyla_api_key = (zyla_api_key if zyla_api_key is not None else os.environ.get("ZYLA_API_KEY") or "").strip()
        self.timeout = max(2.0, float(timeout))
        self.max_retries = max(1, int(max_retries))

    def _has_cloud_credentials(self) -> bool:
        return bool(self.rapidapi_key or self.apify_token or self.zyla_api_key)

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
        """Executes any of the 31 B2B compliance/cyber engines with smart RapidAPI/Zyla/Apify/Preview routing."""
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
                return AuditResult(engine=slug, provider="rapidapi", status="completed_cloud", records=_unwrap_mcp_records(raw), upgrade_url=upgrade_link)

            if self.zyla_api_key and slug in ZYLA_ENDPOINTS:
                raw = self._post_json(ZYLA_ENDPOINTS[slug], {"Authorization": f"Bearer {self.zyla_api_key}"}, safe_payload)
                return AuditResult(engine=slug, provider="zyla", status="completed_cloud", records=_unwrap_mcp_records(raw), upgrade_url=upgrade_link)

            if self.apify_token:
                url = f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
                raw = self._post_json(url, {"Authorization": f"Bearer {self.apify_token}"}, safe_payload)
                return AuditResult(engine=slug, provider="apify", status="completed_cloud", records=_unwrap_mcp_records(raw), upgrade_url=upgrade_link)
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
                "message": "Set RAPIDAPI_API_KEY (BASIC Free 15/mo or PRO $19/mo), ZYLA_API_KEY, or APIFY_API_TOKEN for live cloud datasets.",
                "upgradeUrl": upgrade_link,
            }],
            upgrade_url=upgrade_link,
        )

    def _run_multi_single_key(self, slug: str, items: list[str], build_fn: Any) -> AuditResult:
        if len(items) <= 1 or not self._has_cloud_credentials():
            return self.run_engine(slug, build_fn(items[0]))
        combined: list[dict[str, Any]] = []
        last_res: AuditResult | None = None
        for item in items[:10]:
            res = self.run_engine(slug, build_fn(item))
            last_res = res
            combined.extend(res.records)
            if res.status == "fallback_preview":
                return res
        assert last_res is not None
        return AuditResult(
            engine=last_res.engine,
            provider=last_res.provider,
            status=last_res.status,
            records=combined,
            upgrade_url=last_res.upgrade_url,
        )

    def screen_sanctions(
        self,
        entities: list[str] | str,
        entity_type: str = "ANY",
        max_results: int = 15,
    ) -> AuditResult:
        items = _to_str_list(entities) or ["Acme Global Trading Ltd"]
        return self._run_multi_single_key(
            "global-sanctions-pep-interpol-watchlist-screener",
            items,
            lambda ent: {"entityName": ent, "entityType": str(entity_type or "ANY"), "maxResults": int(max_results)},
        )

    def audit_cisa_kev(
        self,
        cve_ids: list[str] | str,
        only_ransomware: bool = False,
        max_results: int = 15,
    ) -> AuditResult:
        items = _to_str_list(cve_ids) or ["CVE-2024-3094"]
        return self._run_multi_single_key(
            "cisa-kev-ransomware-vulnerability-auditor",
            items,
            lambda kw: {"vendorKeyword": kw, "onlyRansomware": bool(only_ransomware), "maxResults": int(max_results)},
        )

    def verify_eu_vat(
        self,
        vat_numbers: list[str] | str,
        requester_country_code: str = "DE",
        max_results: int = 20,
    ) -> AuditResult:
        items = _to_str_list(vat_numbers) or ["IE6388047V"]
        return self.run_engine(
            "eu-vies-vat-tax-compliance-auditor",
            {
                "vatNumbers": ", ".join(items),
                "requesterCountryCode": str(requester_country_code or "DE"),
                "maxResults": int(max_results),
            },
        )

    def enrich_gleif_lei(
        self,
        queries: list[str] | str,
        country_code: str = "",
        max_results: int = 10,
    ) -> AuditResult:
        items = _to_str_list(queries) or ["Siemens AG"]
        return self._run_multi_single_key(
            "global-gleif-lei-corporate-ownership-kyb",
            items,
            lambda q: {"companyName": q, "countryCode": str(country_code or ""), "maxResults": int(max_results)},
        )

    def scan_ssl_attack_surface(
        self,
        domains: list[str] | str,
        exclude_expired: bool = False,
        max_subdomains: int = 25,
    ) -> AuditResult:
        raw_items = _to_str_list(domains) or ["github.com"]
        cleaned = [d.lower().replace("https://", "").replace("http://", "").split("/")[0] for d in raw_items]
        items = [d for d in cleaned if d] or ["github.com"]
        return self._run_multi_single_key(
            "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
            items,
            lambda dom: {"rootDomain": dom, "excludeExpired": bool(exclude_expired), "maxResults": int(max_subdomains)},
        )

    def audit_brazil_cnpj(
        self,
        cnpjs: list[str] | str,
        include_secondary_cnaes: bool = True,
        max_results: int = 20,
    ) -> AuditResult:
        items = _to_str_list(cnpjs) or ["00000000000191"]
        return self.run_engine(
            "brazil-b2b-cnpj-qsa-lead-enricher",
            {
                "cnpjs": items,
                "includeSecondaryCnaes": bool(include_secondary_cnaes),
                "maxResults": int(max_results),
            },
        )

    def search_sec_edgar(
        self,
        tickers: list[str] | str,
        form_type: str = "ALL",
        keyword: str = "",
        max_results: int = 15,
    ) -> AuditResult:
        items = _to_str_list(tickers) or ["AAPL"]
        return self._run_multi_single_key(
            "us-sec-edgar-filings-insider-radar",
            items,
            lambda tk: {
                "tickerOrCik": tk,
                "formType": str(form_type or "ALL"),
                "keyword": str(keyword or ""),
                "maxResults": int(max_results),
            },
        )


class AsyncB2BComplianceClient:
    """Async wrapper running B2BComplianceClient safely via asyncio.to_thread."""

    def __init__(self, **kwargs: Any) -> None:
        self._sync = B2BComplianceClient(**kwargs)

    async def run_engine(self, engine_slug: str, payload: dict[str, Any] | None = None) -> AuditResult:
        return await asyncio.to_thread(self._sync.run_engine, engine_slug, payload)

    async def screen_sanctions(self, entities: list[str] | str, entity_type: str = "ANY", max_results: int = 15) -> AuditResult:
        return await asyncio.to_thread(self._sync.screen_sanctions, entities, entity_type, max_results)

    async def audit_cisa_kev(self, cve_ids: list[str] | str, only_ransomware: bool = False, max_results: int = 15) -> AuditResult:
        return await asyncio.to_thread(self._sync.audit_cisa_kev, cve_ids, only_ransomware, max_results)

    async def verify_eu_vat(self, vat_numbers: list[str] | str, requester_country_code: str = "DE", max_results: int = 20) -> AuditResult:
        return await asyncio.to_thread(self._sync.verify_eu_vat, vat_numbers, requester_country_code, max_results)

    async def enrich_gleif_lei(self, queries: list[str] | str, country_code: str = "", max_results: int = 10) -> AuditResult:
        return await asyncio.to_thread(self._sync.enrich_gleif_lei, queries, country_code, max_results)

    async def scan_ssl_attack_surface(self, domains: list[str] | str, exclude_expired: bool = False, max_subdomains: int = 25) -> AuditResult:
        return await asyncio.to_thread(self._sync.scan_ssl_attack_surface, domains, exclude_expired, max_subdomains)

    async def audit_brazil_cnpj(self, cnpjs: list[str] | str, include_secondary_cnaes: bool = True, max_results: int = 20) -> AuditResult:
        return await asyncio.to_thread(self._sync.audit_brazil_cnpj, cnpjs, include_secondary_cnaes, max_results)

    async def search_sec_edgar(self, tickers: list[str] | str, form_type: str = "ALL", keyword: str = "", max_results: int = 15) -> AuditResult:
        return await asyncio.to_thread(self._sync.search_sec_edgar, tickers, form_type, keyword, max_results)
