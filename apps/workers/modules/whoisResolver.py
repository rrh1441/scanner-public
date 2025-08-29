"""
whois_resolver.py
-----------------
Resolve live registrant information for a list of domains using:

1. RDAP (free, real-time)
2. Whoxy WHOIS API (paid fallback, `mode=live`)

Author: DealBrief Scanner
Python: 3.11+
Lint:   ruff / black compliant
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Iterable, Mapping

import aiohttp

# ---------------------------  Configuration  -------------------------------- #
WHOXY_API_KEY: Final[str] = os.getenv("WHOXY_API_KEY", "")
if not WHOXY_API_KEY:
    sys.exit("Env var WHOXY_API_KEY is required")

# Adjust if you need more or fewer parallel calls
RDAP_CONCURRENCY: Final[int] = 20
WHOXY_CONCURRENCY: Final[int] = 800  # Whoxy hard limit: 1 000 RPM

# Cache TTLs
RDAP_TTL = timedelta(days=1)
WHOXY_TTL = timedelta(days=1)

# ---------------------------  Data classes   -------------------------------- #


@dataclass(slots=True, frozen=True)
class DomainRecord:
    domain: str
    registrant_name: str | None
    registrant_org: str | None
    registrar: str | None
    creation_date: str | None
    source: str  # "rdap" | "whoxy"
    fetched_at: datetime


# ---------------------------  Helper funcs  -------------------------------- #


def _parse_rdap(json_body: Mapping[str, Any]) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Extract registrant and registrar from an RDAP response.

    RDAP 'entities' list contains entities with roles; choose first with 'registrant'.
    """
    registrant_name = registrant_org = registrar_name = None

    # Registrar is in 'entities' with role 'registrar'
    for entity in json_body.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles and not registrar_name:
            registrar_name = entity.get("name")

    # Registrant fields
    for entity in json_body.get("entities", []):
        if "registrant" not in entity.get("roles", []):
            continue

        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) == 2:
            for vcard_item in vcard[1]:
                if vcard_item[0] == "fn":
                    registrant_name = vcard_item[3]
                if vcard_item[0] == "org":
                    registrant_org = vcard_item[3]
        break

    creation_date = json_body.get("events", [{}])[0].get("eventDate")
    return registrant_name, registrant_org, registrar_name, creation_date


def _parse_whoxy(json_body: Mapping[str, Any]) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Extract registrant and registrar from a Whoxy response.
    """
    # Whoxy returns data in different structure than expected
    registrant_contact = json_body.get("registrant_contact", {})
    domain_registrar = json_body.get("domain_registrar", {})
    
    registrant_name = registrant_contact.get("full_name") or registrant_contact.get("name")
    registrant_org = registrant_contact.get("company_name") or registrant_contact.get("organization")
    registrar_name = domain_registrar.get("registrar_name")
    creation_date = json_body.get("create_date")
    
    return registrant_name, registrant_org, registrar_name, creation_date


# ---------------------------  Resolver class  ------------------------------- #


class WhoisResolver:
    """Resolve WHOIS data using RDAP first, then Whoxy."""

    def __init__(self) -> None:
        self._rdap_semaphore = asyncio.Semaphore(RDAP_CONCURRENCY)
        self._whoxy_semaphore = asyncio.Semaphore(WHOXY_CONCURRENCY)
        self._cache: dict[str, DomainRecord] = {}
        self.rdap_calls = 0
        self.whoxy_calls = 0

    async def resolve_many(self, domains: Iterable[str]) -> list[DomainRecord]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            tasks = [self._resolve_single(session, d.lower().strip()) for d in domains]
            results = await asyncio.gather(*tasks)
            
            # Cost tracking removed from logs
            
            return results

    async def _resolve_single(self, session: aiohttp.ClientSession, domain: str) -> DomainRecord:
        # Return cached value if still fresh
        if (cached := self._cache.get(domain)) and datetime.now(tz=timezone.utc) - cached.fetched_at < RDAP_TTL:
            return cached

        # ------- 1. RDAP ------- #
        try:
            async with self._rdap_semaphore:
                rdap_url = f"https://rdap.org/domain/{domain}"
                async with session.get(rdap_url, headers={"Accept": "application/json"}) as resp:
                    self.rdap_calls += 1
                    if resp.status == 200:
                        body = await resp.json(content_type=None)
                        registrant_name, registrant_org, registrar, created = _parse_rdap(body)
                        if registrant_name or registrant_org:
                            record = DomainRecord(
                                domain,
                                registrant_name,
                                registrant_org,
                                registrar,
                                created,
                                "rdap",
                                datetime.now(tz=timezone.utc),
                            )
                            self._cache[domain] = record
                            return record
        except Exception:
            pass  # fallthrough to Whoxy

        # ------- 2. Whoxy ------- #
        async with self._whoxy_semaphore:
            params = {
                "key": WHOXY_API_KEY,
                "whois": domain,
                "mode": "live",
                "output": "json",
            }
            async with session.get("https://api.whoxy.com/", params=params) as resp:
                self.whoxy_calls += 1
                resp.raise_for_status()
                body = await resp.json(content_type=None)
                registrant_name, registrant_org, registrar, created = _parse_whoxy(body)
                record = DomainRecord(
                    domain,
                    registrant_name,
                    registrant_org,
                    registrar,
                    created,
                    "whoxy",
                    datetime.now(tz=timezone.utc),
                )
                self._cache[domain] = record
                return record


# ---------------------------  CLI (optional)  ------------------------------- #


async def _cli() -> None:
    """Example usage: python whois_resolver.py example.com google.com"""
    domains = sys.argv[1:]
    if not domains:
        sys.exit("Usage: python whois_resolver.py <domain> [<domain> ...]")
    resolver = WhoisResolver()
    records = await resolver.resolve_many(domains)
    for rec in records:
        print(
            json.dumps(
                {
                    "domain": rec.domain,
                    "registrant_name": rec.registrant_name,
                    "registrant_org": rec.registrant_org,
                    "registrar": rec.registrar,
                    "creation_date": rec.creation_date,
                    "source": rec.source,
                    "fetched_at": rec.fetched_at.isoformat(),
                },
                ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    asyncio.run(_cli())