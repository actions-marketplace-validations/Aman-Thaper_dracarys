"""Cross-origin resource sharing misconfiguration (safe, read-only probes).

Replays already-discovered URLs with an attacker-controlled ``Origin`` and reports
only when the server grants that origin *credentialed* access — the case where a
malicious page can actually read an authenticated response. A wildcard origin
without credentials is normal for public APIs and is never reported.
"""
from __future__ import annotations

from urllib.parse import urlparse

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, VulnCategory
from dracarys.scanner.detectors.base import SiteDetector, make_finding
from dracarys.scanner.oracles import cors_permissive

EVIL_ORIGIN = "https://dcrs-evil.example"
MAX_PROBES = 10


class CorsMisconfigDetector:
    id = "cors"

    def _urls(self, ctx) -> list[str]:
        """Distinct GET-able URLs discovered by the crawl, base URL first."""
        seen: dict[str, None] = {ctx.base_url: None}
        for template in ctx.templates:
            if template.method == "GET":
                seen.setdefault(template.url, None)
        return list(seen)[:MAX_PROBES]

    async def run(self, ctx):
        findings = []
        for url in self._urls(ctx):
            ex = await ctx.tool.send(
                "GET", url,
                headers={**ctx.config.auth_headers, "Origin": EVIL_ORIGIN},
                note="cors probe with untrusted origin",
            )
            reason = cors_permissive(EVIL_ORIGIN, ex)
            if reason:
                findings.append(make_finding(
                    detector=self.id, category=VulnCategory.CORS_MISCONFIG,
                    title="CORS policy allows credentialed cross-origin access",
                    url=url, method="GET",
                    detail=f"With Origin: {EVIL_ORIGIN}, the response {reason} while also "
                           "setting Access-Control-Allow-Credentials: true, so a page on any "
                           "origin can read authenticated responses from this endpoint.",
                    evidence=[LabeledExchange("untrusted Origin accepted", ex)],
                    confidence=Confidence.CONFIRMED,
                    dedup_key=f"cors:{urlparse(url).path or '/'}",
                ))
                break  # one finding per target; the policy is site-wide in practice
        return findings


CORS_DETECTORS: list[SiteDetector] = [CorsMisconfigDetector()]
