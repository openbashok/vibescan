#!/usr/bin/env python3
"""
vibescan — agent-readiness scanner + AI footprint recon.

Primary layer (scored 0-100 / 0-10):
  Agent-readiness checks aligned with the Cloudflare emerging standards
  (robots.txt, Sitemap, Link headers, DNS-AID, Markdown negotiation, AI bot
  rules, Content Signals, Web Bot Auth, API Catalog, OAuth, Auth.md, MCP,
  Agent Skills, WebMCP, plus Commerce as info-only).

Secondary layers (do not affect the score):
  - Exposures   : leaked files (.env, .git, CLAUDE.md, AGENTS.md, OpenAPI...)
  - Fingerprint : vibecoding signals (Lovable/v0/Bolt watermarks, host, meta)

Usage:
    python3 vibescan.py target.tld
    python3 vibescan.py target.tld --json
    python3 vibescan.py target.tld --only readiness
    python3 vibescan.py target.tld -v
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterator

DEFAULT_WORKERS = 64

UA = "vibescan/0.6 (+openbash.dev)"
TIMEOUT = 3
DOH = "https://cloudflare-dns.com/dns-query"

# Cached at module load: building an SSL context costs ~10-50ms each time.
# With ~80 HTTP requests per scan, recreating it per-request added up to
# multiple seconds for no good reason.
_SSL_CTX = ssl.create_default_context()


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    max_bytes: int = 256 * 1024,
    follow_redirects: bool = True,
) -> tuple[int | None, dict[str, str], bytes, str]:
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, method=method, headers=hdrs)
    handlers: list = [urllib.request.HTTPSHandler(context=_SSL_CTX)]
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(max_bytes)
            h = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, h, body, resp.geturl()
    except urllib.error.HTTPError as e:
        body = e.read(max_bytes) if hasattr(e, "read") else b""
        h = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, h, body, url
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, ConnectionError, ValueError) as e:
        return None, {}, str(e).encode(), url


def doh(name: str, qtype: int) -> dict | None:
    url = f"{DOH}?name={urllib.parse.quote(name)}&type={qtype}"
    status, _, body, _ = http_request(url, headers={"Accept": "application/dns-json"})
    if status == 200 and body:
        try:
            return json.loads(body)
        except Exception:
            return None
    return None


def normalize(target: str) -> tuple[str, str]:
    if "://" not in target:
        target = "https://" + target
    p = urllib.parse.urlparse(target)
    if not p.netloc:
        raise SystemExit(f"invalid target: {target!r}")
    return f"{p.scheme}://{p.netloc}", p.hostname or p.netloc


def resolve_canonical(base: str) -> tuple[str, str, str]:
    status, _, _, final = http_request(base + "/")
    if status is None or not final:
        return base, urllib.parse.urlparse(base).hostname or base, ""
    p = urllib.parse.urlparse(final)
    new_base = f"{p.scheme}://{p.netloc}"
    note = f"redirected from {base}" if new_base != base else ""
    return new_base, p.hostname or p.netloc, note


def is_html(headers: dict, body: bytes) -> bool:
    ctype = (headers or {}).get("content-type", "").lower()
    if "html" in ctype:
        return True
    head = (body or b"").lstrip()[:200].lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def parse_robots(txt: str) -> list[tuple[str, str, str]]:
    entries, current = [], []
    last_was_ua = False
    for raw in txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            if not last_was_ua:
                current = []
            current.append(val)
            last_was_ua = True
        else:
            for ua in (current or ["*"]):
                entries.append((ua, key, val))
            last_was_ua = False
    return entries


# ============================================================================
# Model
# ============================================================================

@dataclass
class Finding:
    layer: str        # "readiness" | "exposures" | "fingerprint"
    category: str
    name: str
    severity: str     # "critical|high|medium|low|info" (for exposures); else "info"
    status: str       # readiness: "pass|warn|fail|info" — others: "hit|miss|error"
    detail: str = ""
    noise: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class CategoryScore:
    name: str
    passed: float       # supports half points for warns
    total: int
    percent: int


@dataclass
class ReadinessScore:
    overall_100: int
    overall_10: float
    grade: str        # "F" | "D" | "C" | "B" | "A" | "A+"
    categories: list[CategoryScore]


@dataclass
class VerdictItem:
    points: int
    signal: str
    attribution: str


@dataclass
class Verdict:
    score: int
    label: str
    agents: list[str] = field(default_factory=list)
    builders: list[str] = field(default_factory=list)
    evidence: list[VerdictItem] = field(default_factory=list)


# ============================================================================
# Layer 1 (primary): agent-readiness
# ============================================================================

AI_BOTS = [
    "GPTBot", "ChatGPT-User", "OAI-SearchBot",
    "ClaudeBot", "Claude-Web", "anthropic-ai", "Claude-User", "Claude-SearchBot",
    "Google-Extended", "GoogleOther",
    "PerplexityBot", "Perplexity-User",
    "CCBot", "Applebot-Extended", "Bytespider", "Amazonbot",
    "FacebookBot", "Meta-ExternalAgent", "DuckAssistBot", "Cohere-ai",
    "YouBot", "Diffbot", "ImagesiftBot",
]

CONTENT_SIGNALS = ["search", "ai-input", "ai-train"]
AID_PROTOCOLS = ["index", "a2a", "mcp"]
AID_TYPES = [("SVCB", 64), ("HTTPS", 65), ("TXT", 16)]


def _rfind(category: str, name: str, status: str, detail: str = "", evidence: dict | None = None) -> Finding:
    return Finding("readiness", category, name, "info", status, detail, "", evidence or {})


def check_robots_txt(base: str, ctx: dict) -> Finding:
    status, headers, body, _ = http_request(base + "/robots.txt")
    if status != 200 or not body:
        return _rfind("Discoverability", "robots.txt", "fail", f"HTTP {status}")
    ctype = (headers or {}).get("content-type", "")
    if "text/plain" not in ctype.lower():
        return _rfind("Discoverability", "robots.txt", "warn", f"content-type {ctype}")
    txt = body.decode("utf-8", errors="replace")
    ctx["robots_txt"] = txt
    ctx["robots_entries"] = parse_robots(txt)
    if not ctx["robots_entries"]:
        return _rfind("Discoverability", "robots.txt", "warn", "200 but no User-agent")
    return _rfind("Discoverability", "robots.txt", "pass", f"200 {ctype.split(';')[0]}")


def check_sitemap(base: str, ctx: dict) -> Finding:
    sitemaps = []
    for line in (ctx.get("robots_txt") or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    if not sitemaps:
        status, _, body, _ = http_request(base + "/sitemap.xml")
        if status == 200 and body and (b"<urlset" in body or b"<sitemapindex" in body):
            return _rfind("Discoverability", "sitemap", "pass", "/sitemap.xml found")
        return _rfind("Discoverability", "sitemap", "fail", "no sitemap declared or accessible")
    ok = []
    for url in sitemaps:
        status, _, body, _ = http_request(url)
        if status == 200 and body and (b"<urlset" in body or b"<sitemapindex" in body):
            ok.append(url)
    if len(ok) == len(sitemaps):
        return _rfind("Discoverability", "sitemap", "pass",
                      f"{len(ok)}/{len(sitemaps)} valid",
                      evidence={"sitemaps": sitemaps})
    if ok:
        return _rfind("Discoverability", "sitemap", "warn", f"only {len(ok)}/{len(sitemaps)} accessible")
    return _rfind("Discoverability", "sitemap", "fail", "declared sitemaps unreachable")


def check_llms_txt(base: str, ctx: dict) -> Finding:
    """llms.txt (llmstxt.org): a markdown index at the web root that gives
    LLMs a curated map of the site — H1 title, optional blockquote summary,
    then sections of links to the canonical text content. Pass requires
    200 + text/markdown or text/plain + a usable H1.
    """
    status, headers, body, _ = http_request(
        base + "/llms.txt",
        headers={"Accept": "text/markdown, text/plain, */*"},
    )
    if status != 200 or not body:
        return _rfind("Discoverability", "llms.txt", "fail", f"HTTP {status}")
    ctype = (headers or {}).get("content-type", "").lower()
    if "markdown" not in ctype and "plain" not in ctype:
        return _rfind("Discoverability", "llms.txt", "warn",
                      f"present but content-type {ctype or 'unset'}")
    txt = body.decode("utf-8", errors="replace")
    if not re.search(r"^#\s+\S", txt, re.M):
        return _rfind("Discoverability", "llms.txt", "warn",
                      "present but no H1 title")
    return _rfind("Discoverability", "llms.txt", "pass",
                  f"200 {ctype.split(';')[0]}",
                  evidence={"size": len(body)})


def check_link_headers(base: str, ctx: dict) -> Finding:
    status, headers, _, _ = http_request(base + "/")
    if status is None:
        return _rfind("Discoverability", "link headers", "fail", "no response")
    link = (headers or {}).get("link", "")
    if link:
        rels = re.findall(r'rel="?([^",;]+)"?', link)
        return _rfind("Discoverability", "link headers", "pass",
                      f"rels: {', '.join(rels) or '—'}", evidence={"link": link})
    return _rfind("Discoverability", "link headers", "fail", "no Link header on home")


def _is_ip_or_local(host: str) -> bool:
    """Skip DNS-AID for IP literals and localhost — they'll never have
    _index._agents records, and the DoH timeout is ~2s otherwise."""
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def check_dns_aid(base: str, ctx: dict, hosts: list[str]) -> Finding:
    # The primary (canonical) host is hosts[0]; if it's a literal IP or
    # localhost, no DNS-AID records are possible — skip the lookups.
    if hosts and _is_ip_or_local(hosts[0]):
        return _rfind("Discoverability", "DNS-AID", "fail",
                      "skipped (IP literal or localhost — no DNS records possible)")

    # Build the matrix of queries to run in parallel.
    queries: list[tuple[str, str, int]] = []  # (proto_for_name, dns_type_name, dns_type_code)
    for host in hosts:
        for proto in AID_PROTOCOLS:
            name = f"_{proto}._agents.{host}"
            for tname, tcode in AID_TYPES:
                if tname == "TXT" and proto != "index":
                    continue
                queries.append((name, tname, tcode))

    found = []
    dnssec_ok = False
    with cf.ThreadPoolExecutor(max_workers=min(len(queries), 8)) as ex:
        futs = {ex.submit(doh, name, tcode): (name, tname)
                for name, tname, tcode in queries}
        for fut in cf.as_completed(futs):
            name, tname = futs[fut]
            try:
                resp = fut.result()
            except Exception:
                resp = None
            if not resp:
                continue
            if resp.get("Answer"):
                found.append((tname, name))
                if resp.get("AD") is True:
                    dnssec_ok = True

    if found and dnssec_ok:
        return _rfind("Discoverability", "DNS-AID", "pass",
                      f"{found[0][0]} {found[0][1]} (DNSSEC AD=true)",
                      evidence={"records": [f"{t} {n}" for t, n in found], "dnssec": True})
    if found:
        return _rfind("Discoverability", "DNS-AID", "warn",
                      f"{found[0][0]} {found[0][1]} (no DNSSEC)",
                      evidence={"records": [f"{t} {n}" for t, n in found], "dnssec": False})
    return _rfind("Discoverability", "DNS-AID", "fail", "no DNS-AID records")


def check_markdown(base: str, ctx: dict) -> Finding:
    status, headers, _, _ = http_request(base + "/", headers={"Accept": "text/markdown"})
    if status is None:
        return _rfind("Content", "markdown negotiation", "fail", "no response")
    if status >= 400:
        return _rfind("Content", "markdown negotiation", "fail",
                      f"HTTP {status} for Accept: text/markdown")
    ctype = (headers or {}).get("content-type", "").lower()
    if "markdown" in ctype:
        return _rfind("Content", "markdown negotiation", "pass", f"Content-Type: {ctype}")
    return _rfind("Content", "markdown negotiation", "fail",
                  f"served {ctype or 'no content-type'}")


def check_ai_bot_rules(base: str, ctx: dict) -> Finding:
    entries = ctx.get("robots_entries") or []
    if not entries:
        return _rfind("Bot Access Control", "AI bot rules", "fail", "no robots.txt entries")
    declared = {ua.lower() for ua, _, _ in entries}
    matches = [b for b in AI_BOTS if b.lower() in declared]
    has_wildcard = "*" in declared
    if matches:
        return _rfind("Bot Access Control", "AI bot rules", "pass",
                      f"{len(matches)} AI bots: {', '.join(matches[:6])}"
                      + ("…" if len(matches) > 6 else ""),
                      evidence={"matches": matches})
    if has_wildcard:
        return _rfind("Bot Access Control", "AI bot rules", "pass",
                      "wildcard rules apply (covers AI bots)",
                      evidence={"wildcard_only": True})
    return _rfind("Bot Access Control", "AI bot rules", "fail",
                  "no AI bot rules and no wildcard")


def check_content_signals(base: str, ctx: dict) -> Finding:
    # Aligned with isitagentready.com: displayed but NOT scored (info-only).
    txt = ctx.get("robots_txt") or ""
    found = [s for s in CONTENT_SIGNALS
             if re.search(rf"content-signal\s*:\s*[^#\n]*\b{s}\b", txt, re.I)]
    if found:
        return _rfind("Bot Access Control", "Content Signals", "info",
                      f"signals: {', '.join(found)}", evidence={"signals": found})
    return _rfind("Bot Access Control", "Content Signals", "info",
                  "no Content-Signal in robots.txt (not scored)")


def check_web_bot_auth(base: str, ctx: dict) -> Finding:
    path = "/.well-known/http-message-signatures-directory"
    status, headers, body, _ = http_request(base + path, headers={"Accept": "application/json"})
    if status is None:
        return _rfind("Bot Access Control", "Web Bot Auth", "fail", "no response")
    if status != 200:
        return _rfind("Bot Access Control", "Web Bot Auth", "fail", f"HTTP {status}")
    if is_html(headers, body):
        return _rfind("Bot Access Control", "Web Bot Auth", "fail",
                      "soft-404 (HTML)", evidence={})
    try:
        json.loads(body)
        return _rfind("Bot Access Control", "Web Bot Auth", "pass", path)
    except Exception:
        return _rfind("Bot Access Control", "Web Bot Auth", "warn", "200 but not JSON")


def _wellknown_json(category: str, name: str, base: str, paths: list[str],
                    accept: str = "application/json") -> Finding:
    last = ("fail", "not found")
    for path in paths:
        status, headers, body, _ = http_request(base + path, headers={"Accept": accept})
        if status is None:
            last = ("fail", f"{path}: network error")
            continue
        if status != 200:
            last = ("fail", f"{path}: HTTP {status}")
            continue
        if is_html(headers, body):
            last = ("fail", f"{path}: soft-404 (HTML)")
            continue
        try:
            data = json.loads(body)
            ctype = (headers or {}).get("content-type", "").split(";")[0]
            ev = {"path": path, "content_type": ctype}
            if isinstance(data, dict):
                ev["keys"] = list(data.keys())[:20]
            return _rfind(category, name, "pass", f"{path} ({ctype})", evidence=ev)
        except Exception:
            last = ("fail", f"{path}: 200 but invalid JSON")
    return _rfind(category, name, last[0], last[1])


def check_api_catalog(base: str, ctx: dict) -> Finding:
    return _wellknown_json("API, Auth, MCP & Skill Discovery", "API Catalog", base,
                           ["/.well-known/api-catalog"],
                           accept="application/linkset+json, application/json")


def check_oauth_discovery(base: str, ctx: dict) -> Finding:
    return _wellknown_json("API, Auth, MCP & Skill Discovery", "OAuth / OIDC discovery", base,
                           ["/.well-known/openid-configuration",
                            "/.well-known/oauth-authorization-server"])


def check_oauth_pr(base: str, ctx: dict) -> Finding:
    r = _wellknown_json("API, Auth, MCP & Skill Discovery", "OAuth Protected Resource",
                        base, ["/.well-known/oauth-protected-resource"])
    if r.status == "pass":
        return r
    status, headers, _, _ = http_request(base + "/")
    if headers and headers.get("www-authenticate"):
        return _rfind("API, Auth, MCP & Skill Discovery", "OAuth Protected Resource",
                      "warn", f"WWW-Authenticate header present",
                      evidence={"www_authenticate": headers["www-authenticate"][:120]})
    return r


def check_auth_md(base: str, ctx: dict) -> Finding:
    status, headers, body, _ = http_request(base + "/auth.md",
                                            headers={"Accept": "text/markdown, text/plain, */*"})
    if status != 200 or not body:
        return _rfind("API, Auth, MCP & Skill Discovery", "Auth.md", "fail", f"HTTP {status}")
    ctype = (headers or {}).get("content-type", "").lower()
    if "markdown" not in ctype and "plain" not in ctype:
        return _rfind("API, Auth, MCP & Skill Discovery", "Auth.md", "fail",
                      f"content-type {ctype}")
    txt = body.decode("utf-8", errors="replace")
    if re.search(r"^#\s*auth\.md\b", txt, re.I | re.M):
        return _rfind("API, Auth, MCP & Skill Discovery", "Auth.md", "pass",
                      "/auth.md with valid H1")
    return _rfind("API, Auth, MCP & Skill Discovery", "Auth.md", "warn",
                  "/auth.md exists, no canonical H1")


def check_mcp(base: str, ctx: dict) -> Finding:
    return _wellknown_json("API, Auth, MCP & Skill Discovery", "MCP Server Card", base,
                           ["/.well-known/mcp/server-card.json",
                            "/.well-known/mcp/server-cards.json",
                            "/.well-known/mcp.json"])


def check_agent_skills(base: str, ctx: dict) -> Finding:
    return _wellknown_json("API, Auth, MCP & Skill Discovery", "Agent Skills index", base,
                           ["/.well-known/agent-skills/index.json"])


def check_webmcp(base: str, ctx: dict) -> Finding:
    # isitagentready.com runs headless browser to test navigator.modelContext;
    # we can only check via HTTP, so we default to fail (matching their default
    # when no WebMCP tools are detected).
    return _rfind("API, Auth, MCP & Skill Discovery", "WebMCP", "fail",
                  "no WebMCP detected (HTTP-only check)")


def check_x402(base: str, ctx: dict) -> Finding:
    for path in ("/", "/api", "/api/v1"):
        status, _, _, _ = http_request(base + path)
        if status == 402:
            return _rfind("Commerce", "x402", "pass", f"{path} returned 402")
    return _rfind("Commerce", "x402", "fail", "no 402 response")


def check_mpp(base: str, ctx: dict) -> Finding:
    status, headers, body, _ = http_request(base + "/openapi.json",
                                            headers={"Accept": "application/json"})
    if status != 200 or not body or is_html(headers, body):
        return _rfind("Commerce", "MPP", "fail", "/openapi.json absent or HTML")
    try:
        spec = json.loads(body)
    except Exception:
        return _rfind("Commerce", "MPP", "fail", "/openapi.json not parseable")
    found = 0
    for path_item in (spec.get("paths") or {}).values():
        if not isinstance(path_item, dict):
            continue
        for op in path_item.values():
            if isinstance(op, dict) and "x-payment-info" in op:
                found += 1
    if found:
        return _rfind("Commerce", "MPP", "pass", f"{found} operation(s) with x-payment-info")
    return _rfind("Commerce", "MPP", "fail", "/openapi.json without x-payment-info")


def check_ucp(base: str, ctx: dict) -> Finding:
    return _wellknown_json("Commerce", "UCP", base,
                           ["/.well-known/ucp", "/.well-known/ucp.json"])


def check_acp(base: str, ctx: dict) -> Finding:
    return _wellknown_json("Commerce", "ACP", base,
                           ["/.well-known/acp.json", "/.well-known/acp"])


def scan_readiness(base: str, host: str, workers: int = DEFAULT_WORKERS) -> Iterator[Finding]:
    """robots.txt has to come first (sitemap / AI bot rules / Content Signals
    all read its parsed entries from ctx). Everything else is independent and
    runs in parallel; yielded in submission order.
    """
    ctx: dict = {}
    aid_hosts = [host]
    apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 2 else host
    if apex != host:
        aid_hosts.append(apex)

    # Phase 1: robots.txt populates ctx for the parallel phase
    yield check_robots_txt(base, ctx)

    # Phase 2: everything else, parallel-but-ordered
    rest: list[Callable[[], Finding]] = [
        lambda: check_sitemap(base, ctx),
        lambda: check_link_headers(base, ctx),
        lambda: check_dns_aid(base, ctx, aid_hosts),
        lambda: check_llms_txt(base, ctx),
        lambda: check_markdown(base, ctx),
        lambda: check_ai_bot_rules(base, ctx),
        lambda: check_content_signals(base, ctx),
        lambda: check_web_bot_auth(base, ctx),
        lambda: check_api_catalog(base, ctx),
        lambda: check_oauth_discovery(base, ctx),
        lambda: check_oauth_pr(base, ctx),
        lambda: check_auth_md(base, ctx),
        lambda: check_mcp(base, ctx),
        lambda: check_agent_skills(base, ctx),
        lambda: check_webmcp(base, ctx),
        lambda: check_x402(base, ctx),
        lambda: check_mpp(base, ctx),
        lambda: check_ucp(base, ctx),
        lambda: check_acp(base, ctx),
    ]
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fn) for fn in rest]
        for fut in cf.as_completed(futs):
            yield fut.result()


SCORED_CATEGORIES = [
    "Discoverability",
    "Content",
    "Bot Access Control",
    "API, Auth, MCP & Skill Discovery",
]


def compute_readiness_score(findings: list[Finding]) -> ReadinessScore:
    """Score formula aligned with isitagentready.com:
    overall = (Σ passes across all scored items) / (Σ scored items) × 100.
    Info-only checks (Content Signals) are NOT counted. Warns count as 0.
    """
    cats: dict[str, list[Finding]] = {}
    for f in findings:
        if f.layer != "readiness":
            continue
        if f.status == "info":
            continue  # info-only checks (Content Signals) not counted
        cats.setdefault(f.category, []).append(f)

    category_scores: list[CategoryScore] = []
    total_passed = 0
    total_items = 0
    for cat in SCORED_CATEGORIES:
        items = cats.get(cat, [])
        if not items:
            continue
        passed = sum(1 for f in items if f.status == "pass")
        total = len(items)
        pct = round(passed / total * 100) if total else 0
        category_scores.append(CategoryScore(cat, passed, total, pct))
        total_passed += passed
        total_items += total

    overall_100 = round(total_passed / total_items * 100) if total_items else 0
    overall_10 = round(overall_100 / 10, 1)

    if overall_100 < 20:
        grade = "F"
    elif overall_100 < 40:
        grade = "D"
    elif overall_100 < 60:
        grade = "C"
    elif overall_100 < 80:
        grade = "B"
    elif overall_100 < 95:
        grade = "A"
    else:
        grade = "A+"

    return ReadinessScore(overall_100, overall_10, grade, category_scores)


# ============================================================================
# Layer 2 (secondary): exposures
# ============================================================================

EXPOSURE_TARGETS: list[tuple[str, str, str, str | None]] = [
    ("Coding agents",   "/CLAUDE.md",                       "high",     "text"),
    ("Coding agents",   "/AGENTS.md",                       "high",     "text"),
    ("Coding agents",   "/AGENT.md",                        "high",     "text"),
    ("Coding agents",   "/.cursorrules",                    "high",     None),
    ("Coding agents",   "/.windsurfrules",                  "high",     None),
    ("Coding agents",   "/.aider.conf.yml",                 "high",     None),
    ("Coding agents",   "/.aider.chat.history.md",          "high",     "text"),
    ("Coding agents",   "/.aider.input.history",            "high",     None),
    ("Coding agents",   "/.github/copilot-instructions.md", "high",     "text"),
    ("Coding agents",   "/.continue/config.json",           "high",     "json"),
    ("Coding agents",   "/.claude/settings.json",           "high",     "json"),
    ("Coding agents",   "/.claude/settings.local.json",     "critical", "json"),
    ("Coding agents",   "/.cursor/mcp.json",                "high",     "json"),
    ("Coding agents",   "/.codex/config.toml",              "high",     None),
    ("Coding agents",   "/.specstory/",                     "medium",   None),

    ("Exposed VCS",     "/.git/config",                     "critical", None),
    ("Exposed VCS",     "/.git/HEAD",                       "critical", None),
    ("Exposed VCS",     "/.git/logs/HEAD",                  "critical", None),
    ("Exposed VCS",     "/.git/index",                      "critical", None),
    ("Exposed VCS",     "/.gitignore",                      "low",      "text"),
    ("Exposed VCS",     "/.svn/entries",                    "critical", None),
    ("Exposed VCS",     "/.hg/hgrc",                        "critical", None),

    ("Secrets / config","/.env",                            "critical", None),
    ("Secrets / config","/.env.local",                      "critical", None),
    ("Secrets / config","/.env.production",                 "critical", None),
    ("Secrets / config","/.env.development",                "critical", None),
    ("Secrets / config","/.env.backup",                     "critical", None),
    ("Secrets / config","/.env.bak",                        "critical", None),
    ("Secrets / config","/credentials.json",                "critical", "json"),
    ("Secrets / config","/secrets.json",                    "critical", "json"),
    ("Secrets / config","/config.json",                     "medium",   "json"),
    ("Secrets / config","/settings.json",                   "medium",   "json"),
    ("Secrets / config","/docker-compose.yml",              "high",     None),
    ("Secrets / config","/Dockerfile",                      "medium",   None),

    ("IDE / OS",        "/.vscode/settings.json",           "medium",   "json"),
    ("IDE / OS",        "/.idea/workspace.xml",             "medium",   None),
    ("IDE / OS",        "/.DS_Store",                       "medium",   None),

    ("Backups / dumps", "/backup.sql",                      "critical", None),
    ("Backups / dumps", "/dump.sql",                        "critical", None),
    ("Backups / dumps", "/database.sql",                    "critical", None),
    ("Backups / dumps", "/db.sqlite",                       "critical", None),
    ("Backups / dumps", "/backup.zip",                      "high",     None),
    ("Backups / dumps", "/backup.tar.gz",                   "high",     None),

    ("Public lockfiles","/package-lock.json",               "low",      "json"),
    ("Public lockfiles","/yarn.lock",                       "low",      None),
    ("Public lockfiles","/pnpm-lock.yaml",                  "low",      None),
    ("Public lockfiles","/composer.lock",                   "low",      "json"),
    ("Public lockfiles","/Pipfile.lock",                    "low",      "json"),
    ("Public lockfiles","/poetry.lock",                     "low",      None),
]

EXPOSURE_VALIDATORS: dict[str, re.Pattern] = {
    "/.git/config":    re.compile(rb"\[core\]|\[remote\b|\[branch\b", re.I),
    "/.git/HEAD":      re.compile(rb"^ref:\s*refs/", re.I),
    "/.git/logs/HEAD": re.compile(rb"^[0-9a-f]{40}\s+[0-9a-f]{40}", re.I | re.M),
    "/.git/index":     re.compile(rb"^DIRC", re.I),
    "/.svn/entries":   re.compile(rb"^\d+\s*$|^<\?xml", re.I | re.M),
    "/.DS_Store":      re.compile(rb"^\x00\x00\x00\x01Bud1"),
}

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key",    re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws_secret_hint",   re.compile(rb"aws_secret_access_key\s*=\s*\S+", re.I)),
    ("openai_key",        re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic_key",     re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("google_api_key",    re.compile(rb"AIza[0-9A-Za-z\-_]{35}")),
    ("github_token",      re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack_token",       re.compile(rb"xox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_key",        re.compile(rb"sk_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("generic_kv",        re.compile(rb"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD)\s*=\s*['\"]?[A-Za-z0-9_\-]{8,}", re.I)),
]

BLOCK_STATUSES = {401, 403, 406, 429}


def _grep_secrets(body: bytes) -> list[dict]:
    out: list[dict] = []
    for label, pat in SECRET_PATTERNS:
        m = pat.search(body)
        if m:
            sample = m.group(0)[:60].decode("utf-8", errors="replace")
            out.append({"pattern": label, "sample": sample})
    return out


def check_exposure(base: str, category: str, path: str, severity: str, expected_ctype: str | None) -> Finding:
    status, headers, body, _ = http_request(base + path, follow_redirects=False)
    if status is None:
        return Finding("exposures", category, path, "info", "error", "no response")
    if status in BLOCK_STATUSES:
        return Finding("exposures", category, path, "info", "miss", f"HTTP {status}", noise="blocked")
    if status != 200:
        return Finding("exposures", category, path, "info", "miss", f"HTTP {status}")
    if not body:
        return Finding("exposures", category, path, "info", "miss", "empty body")
    if is_html(headers, body) and expected_ctype != "html":
        return Finding("exposures", category, path, "info", "miss", "", noise="soft-404")
    validator = EXPOSURE_VALIDATORS.get(path)
    if validator and not validator.search(body[:2048]):
        return Finding("exposures", category, path, "info", "miss", "validator mismatch", noise="inconclusive")

    detail = "exposed"
    evidence: dict = {"size": len(body), "content_type": (headers or {}).get("content-type", "")}
    if path.startswith("/.env") or path in ("/.git/config", "/credentials.json",
                                            "/secrets.json", "/docker-compose.yml"):
        secrets = _grep_secrets(body)
        if secrets:
            evidence["secrets_found"] = secrets
    return Finding("exposures", category, path, severity, "hit", detail, "", evidence)


def check_openapi_public(base: str) -> Finding:
    status, headers, body, _ = http_request(base + "/openapi.json",
                                            headers={"Accept": "application/json"})
    if status != 200 or not body or is_html(headers, body):
        return Finding("exposures", "API surface", "/openapi.json", "info", "miss",
                       "no public OpenAPI", noise="soft-404" if is_html(headers, body) else "")
    try:
        spec = json.loads(body)
    except Exception:
        return Finding("exposures", "API surface", "/openapi.json", "low", "hit",
                       "200 but invalid JSON")
    paths = list((spec.get("paths") or {}).keys())
    title = (spec.get("info") or {}).get("title", "")
    return Finding("exposures", "API surface", "/openapi.json", "medium", "hit",
                   f"public spec ({len(paths)} paths)",
                   evidence={"paths_sample": paths[:25], "title": title})


def scan_exposures(base: str, workers: int = DEFAULT_WORKERS) -> Iterator[Finding]:
    """Probe all exposure targets in parallel; yield each finding as soon as
    its HTTP request finishes (out-of-submission-order). This makes the
    output a smooth waterfall instead of a staircase of bursts.
    """
    def safe(cat: str, path: str, sev: str, ct: str | None) -> Finding:
        try:
            return check_exposure(base, cat, path, sev, ct)
        except Exception as e:
            return Finding("exposures", cat, path, "info", "error", f"exception: {e}")

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(safe, c, p, s, ct) for c, p, s, ct in EXPOSURE_TARGETS]
        futs.append(ex.submit(check_openapi_public, base))
        for fut in cf.as_completed(futs):
            yield fut.result()


# ============================================================================
# Layer 3 (secondary): fingerprint (vibecoding detection)
# ============================================================================

REVEALING_HEADERS = ["server", "x-powered-by", "x-vercel-id",
                     "x-render-origin-server", "x-served-by", "via"]

BUILDER_HOST_SUFFIXES = [
    "vercel.app", "netlify.app", "lovableproject.com", "bolt.host",
    "replit.dev", "repl.co", "web.app", "firebaseapp.com", "pages.dev",
    "onrender.com", "up.railway.app", "base44.app",
]

BUILDER_BLOB_PATTERNS = [
    ("lovable",           re.compile(r"lovable", re.I)),
    ("v0.dev",            re.compile(r"v0\.dev|vercel\.com/v0|data-v0", re.I)),
    ("bolt.new",          re.compile(r"bolt\.new|stackblitz", re.I)),
    ("base44",            re.compile(r"base44", re.I)),
    ("replit",            re.compile(r"replit\.com|created with replit", re.I)),
    ("gpt-engineer",      re.compile(r"gptengineer|gpt-engineer", re.I)),
    ("ai_watermark",      re.compile(r"generated by (chatgpt|claude|copilot|cursor)", re.I)),
    ("made_with_badge",   re.compile(r"made with (lovable|bubble|softr|framer)", re.I)),
]

SUPABASE_ANON_PATTERN = re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def scan_fingerprint(base: str, host: str) -> Iterator[Finding]:
    status, headers, body, _ = http_request(base + "/")
    if status is None:
        yield Finding("fingerprint", "Home", "home", "info", "error", "no response")
        return
    html = body.decode("utf-8", errors="replace")

    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m:
        yield Finding("fingerprint", "Stack", "meta generator", "info", "hit",
                      m.group(1)[:120], evidence={"value": m.group(1)})

    revealed = {h: headers.get(h) for h in REVEALING_HEADERS if headers.get(h)}
    if revealed:
        joined = ", ".join(f"{k}={v[:40]}" for k, v in revealed.items())
        yield Finding("fingerprint", "Stack", "revealing headers", "info", "hit",
                      joined, evidence={"headers": revealed})

    suffix_hit = next((s for s in BUILDER_HOST_SUFFIXES if host.endswith(s)), None)
    if suffix_hit:
        yield Finding("fingerprint", "Host", "prototyping host suffix", "info", "hit",
                      f"{host} ({suffix_hit})", evidence={"suffix": suffix_hit})

    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)[:8]
    blob = html
    for s in srcs:
        u = urllib.parse.urljoin(base + "/", s)
        st, _, b, _ = http_request(u)
        if st == 200 and b and len(b) < 2_000_000:
            blob += "\n" + b.decode("utf-8", errors="replace")

    for label, pat in BUILDER_BLOB_PATTERNS:
        m = pat.search(blob)
        if m:
            yield Finding("fingerprint", "Builders", label, "info", "hit",
                          m.group(0)[:80], evidence={"match": m.group(0)[:200]})

    m = SUPABASE_ANON_PATTERN.search(blob)
    if m:
        yield Finding("fingerprint", "Other", "supabase anon JWT in bundle", "low", "hit",
                      "JWT HS256 embedded", evidence={"sample": m.group(0)[:60]})


# ============================================================================
# Vibecoding verdict (uses exposures + fingerprint findings)
# ============================================================================

SCORE_EXPOSURE_PATHS: dict[str, tuple[int, str]] = {
    "/CLAUDE.md":                       (15, "Claude"),
    "/AGENTS.md":                       (15, "Agent context"),
    "/AGENT.md":                        (15, "Agent context"),
    "/.cursorrules":                    (15, "Cursor"),
    "/.windsurfrules":                  (15, "Windsurf"),
    "/.aider.conf.yml":                 (15, "Aider"),
    "/.aider.chat.history.md":          (15, "Aider"),
    "/.aider.input.history":            (15, "Aider"),
    "/.github/copilot-instructions.md": (15, "Copilot"),
    "/.continue/config.json":           (12, "Continue"),
    "/.claude/settings.json":           (12, "Claude"),
    "/.claude/settings.local.json":     (12, "Claude"),
    "/.cursor/mcp.json":                (12, "Cursor"),
    "/.codex/config.toml":              (12, "Codex"),
    "/.specstory/":                     (12, "SpecStory"),
}

SCORE_BUILDER_PATTERNS: dict[str, tuple[int, str]] = {
    "ai_watermark":    (15, "AI-generated watermark"),
    "lovable":         (12, "Lovable"),
    "v0.dev":          (12, "v0.dev"),
    "bolt.new":        (12, "bolt.new"),
    "base44":          (12, "Base44"),
    "gpt-engineer":    (12, "GPT-Engineer"),
    "made_with_badge": (10, "Builder badge"),
    "replit":          (8,  "Replit"),
}

SCORE_HOST_SUFFIX: dict[str, tuple[int, str]] = {
    "lovableproject.com": (10, "Lovable"),
    "bolt.host":          (10, "bolt.new"),
    "base44.app":         (10, "Base44"),
    "replit.dev":         (6,  "Replit"),
    "repl.co":            (6,  "Replit"),
    "vercel.app":         (2,  "Vercel hosting"),
    "netlify.app":        (2,  "Netlify hosting"),
    "pages.dev":          (2,  "Cloudflare Pages"),
    "web.app":            (2,  "Firebase hosting"),
    "firebaseapp.com":    (2,  "Firebase hosting"),
}

META_GENERATOR_KEYWORDS = ["lovable", "v0", "bolt", "base44", "framer", "wix", "webflow", "bubble", "softr"]

AGENT_NAMES = {"Claude", "Cursor", "Aider", "Copilot", "Continue", "Codex", "Windsurf",
               "SpecStory", "Agent context", "AI-generated watermark"}


def compute_verdict(findings: list[Finding]) -> Verdict:
    items: list[VerdictItem] = []
    seen: set[tuple[str, str]] = set()

    def push(points: int, signal: str, attribution: str) -> None:
        key = (signal, attribution)
        if key in seen:
            return
        seen.add(key)
        items.append(VerdictItem(points, signal, attribution))

    for f in findings:
        if f.status != "hit":
            continue
        if f.layer == "exposures" and f.name in SCORE_EXPOSURE_PATHS:
            pts, attr = SCORE_EXPOSURE_PATHS[f.name]
            push(pts, f"{f.name} exposed", attr)
        elif f.layer == "fingerprint":
            if f.name in SCORE_BUILDER_PATTERNS:
                pts, attr = SCORE_BUILDER_PATTERNS[f.name]
                push(pts, f"watermark: {f.name}", attr)
            elif f.name == "prototyping host suffix":
                suffix = f.evidence.get("suffix")
                if suffix and suffix in SCORE_HOST_SUFFIX:
                    pts, attr = SCORE_HOST_SUFFIX[suffix]
                    push(pts, f"host on {suffix}", attr)
            elif f.name == "meta generator":
                val = (f.evidence.get("value") or "").lower()
                for kw in META_GENERATOR_KEYWORDS:
                    if kw in val:
                        push(8, f'<meta generator="{f.detail}">', kw.title())
                        break

    score = sum(i.points for i in items)
    agents = sorted({i.attribution for i in items if i.attribution in AGENT_NAMES})
    builders = sorted({i.attribution for i in items if i.attribution not in AGENT_NAMES})
    return Verdict(score=score, label="", agents=agents, builders=builders,
                   evidence=sorted(items, key=lambda x: -x.points))


# ============================================================================
# Renderer
# ============================================================================

class Color:
    OK = "\033[32m"
    FAIL = "\033[31m"
    WARN = "\033[33m"
    INFO = "\033[36m"
    BLUE = "\033[34m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def disable_color() -> None:
    for k in ("OK", "FAIL", "WARN", "INFO", "BLUE", "DIM", "BOLD", "END"):
        setattr(Color, k, "")


def _truncate(text: str, width: int) -> str:
    if width <= 1 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _slugify(s: str) -> str:
    s = s.strip("/").replace("/", "-").replace(".", "-").replace("_", "-")
    s = re.sub(r"[^a-zA-Z0-9\-:]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-").lower()
    return s


def derive_check_id(f: Finding) -> str:
    if f.layer == "readiness":
        return _slugify(f.name)
    if f.layer == "exposures":
        return _slugify(f.name)
    if f.layer == "fingerprint":
        return _slugify(f.name)
    return _slugify(f.name)


def status_color(layer: str, status: str, severity: str) -> str:
    if layer == "readiness":
        return {"pass": Color.OK, "warn": Color.WARN, "fail": Color.FAIL,
                "info": Color.INFO}.get(status, Color.DIM)
    if status == "hit":
        return {"critical": Color.FAIL + Color.BOLD, "high": Color.FAIL,
                "medium": Color.WARN, "low": Color.BLUE,
                "info": Color.INFO}.get(severity, Color.INFO)
    return Color.DIM


def status_tag(f: Finding) -> str:
    if f.layer == "readiness":
        return f.status
    if f.status == "hit":
        return f.severity
    return "-"


def derive_tags(f: Finding) -> list[str]:
    tags: list[str] = []
    if f.noise:
        tags.append(f.noise)
    if f.evidence.get("secrets_found"):
        for s in f.evidence["secrets_found"][:6]:
            tags.append(s["pattern"])
    if f.evidence.get("suffix"):
        tags.append(f.evidence["suffix"])
    if f.evidence.get("value") and f.layer == "fingerprint":
        tags.append(_truncate(f.evidence["value"], 40))
    if f.evidence.get("title"):
        tags.append(_truncate(f.evidence["title"], 30))
    paths_sample = f.evidence.get("paths_sample")
    if paths_sample:
        tags.append(f"{len(paths_sample)}-paths")
    if f.evidence.get("dnssec") is True:
        tags.append("dnssec")
    if f.evidence.get("wildcard_only"):
        tags.append("wildcard-only")
    return tags


def derive_url(f: Finding, base: str, host: str) -> str:
    if f.layer == "exposures":
        return base + f.name
    if f.layer == "fingerprint":
        return base + "/"
    if f.layer == "readiness":
        if f.category == "Discoverability" and f.name == "DNS-AID":
            recs = f.evidence.get("records") or []
            if recs:
                return f"dns://{recs[0].split(' ', 1)[1]}"
            return f"dns://_index._agents.{host}"
        if f.name == "robots.txt":
            return base + "/robots.txt"
        if f.name == "llms.txt":
            return base + "/llms.txt"
        if f.name in ("link headers", "markdown negotiation"):
            return base + "/"
        if f.name == "sitemap":
            sm = (f.evidence.get("sitemaps") or [None])[0]
            return sm or base + "/sitemap.xml"
        if f.name == "AI bot rules" or f.name == "Content Signals":
            return base + "/robots.txt"
        if f.name == "Web Bot Auth":
            return base + "/.well-known/http-message-signatures-directory"
        if f.name == "Auth.md":
            return base + "/auth.md"
        if f.name == "WebMCP":
            return base + "/"
        if f.name == "MPP":
            return base + "/openapi.json"
        if f.name == "x402":
            return base + "/"
        # well-known JSONs use evidence.path
        path = f.evidence.get("path")
        if path:
            return base + path
        # fallback by name → well-known
        wk = {
            "API Catalog": "/.well-known/api-catalog",
            "OAuth / OIDC discovery": "/.well-known/openid-configuration",
            "OAuth Protected Resource": "/.well-known/oauth-protected-resource",
            "MCP Server Card": "/.well-known/mcp/server-card.json",
            "Agent Skills index": "/.well-known/agent-skills/index.json",
            "UCP": "/.well-known/ucp.json",
            "ACP": "/.well-known/acp.json",
        }
        return base + wk.get(f.name, "/")
    return base


class Renderer:
    def __init__(self, width: int, verbose: bool,
                 animated: bool = True, dot_ms: int = 18, min_dots: int = 3):
        self.width = max(80, width)
        self.verbose = verbose
        self.animated = animated
        self.dot_ms = dot_ms
        self.min_dots = min_dots
        self.all: list[Finding] = []
        self.base: str = ""
        self.host: str = ""
        self._last_t: float | None = None

    # ---- timed output primitives ----

    def _ts(self) -> str:
        """Per-line timing prefix: ms since the last printed line.
        Lets the operator spot the slow checks at a glance.
        """
        now = time.perf_counter()
        delta = 0.0 if self._last_t is None else now - self._last_t
        self._last_t = now
        if delta < 1.0:
            return f"{Color.DIM}[+{int(delta * 1000):>4}ms]{Color.END} "
        return f"{Color.DIM}[+{delta:>5.2f}s]{Color.END} "

    def line(self, msg: str) -> None:
        print(self._ts() + msg, flush=True)

    def blank(self) -> None:
        print(flush=True)

    def separator(self) -> None:
        self.blank()
        self.line(f"{Color.DIM}{'─' * min(self.width, 90)}{Color.END}")
        self.blank()

    # ---- public API ----

    def banner(self, version: str) -> None:
        self.line(f"{Color.BOLD}    vibescan{Color.END} {Color.DIM}{version}{Color.END}")
        self.line(f"    {Color.DIM}AI/agent footprint recon  ·  openbash.dev{Color.END}")
        self.blank()

    def info(self, msg: str) -> None:
        self.line(f"{Color.INFO}[INF]{Color.END} {msg}")

    def set_context(self, base: str, host: str) -> None:
        self.base = base
        self.host = host

    def feed(self, f: Finding) -> None:
        self.all.append(f)
        if self.animated:
            # Animated mode is for live demos / interactive runs. Show every
            # check the scanner actually performs — hit or miss — so the
            # console reflects the real volume of work, not just the
            # "interesting" results.
            self._render_animated(f)
            return
        # Plain mode (scripted / piped): only the meaningful lines unless
        # --verbose is set.
        is_hit_or_readiness = (f.layer == "readiness") or (f.status in ("hit", "error"))
        if is_hit_or_readiness or self.verbose:
            self._render(f)

    # ---- animated rendering (default) ----
    #
    # The line for each finding prints sequentially as it arrives from the
    # parallel scanner — label first, dots animated for visibility, then
    # the [STATUS] tag. Scan execution is fully parallel via as_completed;
    # the animation is the per-line UX, not the work itself.

    def _demo_label(self, f: Finding) -> str:
        if f.layer == "readiness":
            verbs = {
                "robots.txt":               "Fetching",
                "llms.txt":                 "Fetching",
                "sitemap":                  "Discovering",
                "link headers":             "Reading",
                "DNS-AID":                  "Resolving",
                "markdown negotiation":     "Negotiating",
                "AI bot rules":             "Parsing",
                "Content Signals":          "Parsing",
                "Web Bot Auth":             "Probing",
                "API Catalog":              "Probing",
                "OAuth / OIDC discovery":   "Probing",
                "OAuth Protected Resource": "Probing",
                "Auth.md":                  "Reading",
                "MCP Server Card":          "Probing",
                "Agent Skills index":       "Probing",
                "WebMCP":                   "Checking",
                "x402":                     "Probing",
                "MPP":                      "Inspecting",
                "UCP":                      "Probing",
                "ACP":                      "Probing",
            }
            return f"{verbs.get(f.name, 'Checking')} {f.name}"
        if f.layer == "exposures":
            return f"Probing {f.name}"
        if f.layer == "fingerprint":
            return f"Inspecting {f.name}"
        return f.name

    def _demo_status(self, f: Finding) -> tuple[str, str]:
        if f.layer == "readiness":
            if f.status == "pass":
                return "PASS", Color.OK + Color.BOLD
            if f.status == "warn":
                return "WARN", Color.WARN
            if f.status == "info":
                return "INFO", Color.INFO
            if f.noise:
                return "SKIP", Color.DIM
            return "FAIL", Color.FAIL
        if f.layer == "exposures":
            if f.status == "hit":
                return "FOUND", Color.WARN
            return "----", Color.DIM
        # fingerprint
        if f.status == "hit":
            return "FOUND", Color.INFO
        return "----", Color.DIM

    def _render_animated(self, f: Finding) -> None:
        label = self._demo_label(f)
        status, status_col = self._demo_status(f)

        LABEL_W = min(44, max(30, self.width - 22))
        label_disp = label[:LABEL_W].ljust(LABEL_W)

        sys.stdout.write(f"  {label_disp} ")
        sys.stdout.flush()
        tick = self.dot_ms / 1000.0
        for _ in range(self.min_dots):
            time.sleep(tick)
            sys.stdout.write(f"{Color.DIM}.{Color.END}")
            sys.stdout.flush()
        sys.stdout.write(f"  [{status_col}{status:^8}{Color.END}]\n")
        sys.stdout.flush()

    def _render(self, f: Finding) -> None:
        cid = derive_check_id(f)
        layer = f.layer
        tag = status_tag(f)
        col = status_color(f.layer, f.status, f.severity)
        url = derive_url(f, self.base, self.host)
        tags = derive_tags(f)

        # Compute available width budget: the timing prefix occupies ~10 chars
        head_plain = f"[{cid}] [{layer}] [{tag}]"
        tag_plain = f" [{','.join(tags)}]" if tags else ""
        used = 10 + len(head_plain) + len(tag_plain) + 1
        avail = max(30, self.width - used)
        url_short = _truncate(url, avail)

        line = (
            f"{Color.DIM}[{Color.END}{Color.OK}{cid}{Color.END}{Color.DIM}]{Color.END} "
            f"{Color.DIM}[{Color.END}{Color.BLUE}{layer}{Color.END}{Color.DIM}]{Color.END} "
            f"{Color.DIM}[{Color.END}{col}{tag}{Color.END}{Color.DIM}]{Color.END} "
        )
        line += url_short if f.status in ("pass", "hit", "warn", "info", "error") else f"{Color.DIM}{url_short}{Color.END}"
        if tags:
            line += f" {Color.DIM}[{','.join(tags)}]{Color.END}"
        self.line(line)

    def summary(self, elapsed: float) -> None:
        readiness_n = sum(1 for f in self.all if f.layer == "readiness")
        exposures_hits = sum(1 for f in self.all if f.layer == "exposures" and f.status == "hit")
        exposures_total = sum(1 for f in self.all if f.layer == "exposures")
        fp_hits = sum(1 for f in self.all if f.layer == "fingerprint" and f.status == "hit")
        self.blank()
        self.info(f"scan completed in {elapsed:.2f}s")
        self.info(f"readiness checks: {readiness_n}  ·  "
                  f"exposures: {exposures_hits} hits / {exposures_total}  ·  "
                  f"fingerprint: {fp_hits} hits")

    def score(self, s: ReadinessScore) -> None:
        grade_col = {
            "F":  Color.FAIL + Color.BOLD,
            "D":  Color.FAIL,
            "C":  Color.WARN,
            "B":  Color.INFO,
            "A":  Color.OK,
            "A+": Color.OK + Color.BOLD,
        }.get(s.grade, Color.INFO)
        self.blank()
        self.line(f"{Color.BOLD}[SCORE]{Color.END}  "
                  f"Agent-Readiness  "
                  f"{grade_col}{Color.BOLD}{s.overall_100}/100{Color.END}  "
                  f"{Color.DIM}·{Color.END}  "
                  f"{grade_col}{Color.BOLD}{s.grade}{Color.END}")
        for cs in s.categories:
            bar_w = 20
            filled = round(cs.percent / 100 * bar_w)
            bar = "█" * filled + "·" * (bar_w - filled)
            ratio = f"{cs.passed:g}/{cs.total}"
            col_cat = (Color.FAIL if cs.percent < 25 else
                       Color.WARN if cs.percent < 50 else
                       Color.OK)
            self.line(f"  {cs.name:<36}  {col_cat}{cs.percent:>3}/100{Color.END}  "
                      f"{Color.DIM}{bar} {ratio}{Color.END}")

    def verdict(self, v: Verdict) -> None:
        self.blank()
        n_agents = len(v.agents)
        n_builders = len(v.builders)
        self.line(f"{Color.BOLD}[VIBECODING]{Color.END}  "
                  f"score {Color.BOLD}{v.score} pts{Color.END}  "
                  f"{Color.DIM}·{Color.END}  "
                  f"{n_agents} agent(s), {n_builders} builder(s) detected")
        if not v.evidence:
            return
        self.line(f"  {Color.DIM}agents:  {Color.END} "
                  f"{', '.join(v.agents) if v.agents else '—'}")
        self.line(f"  {Color.DIM}builders:{Color.END} "
                  f"{', '.join(v.builders) if v.builders else '—'}")
        self.line(f"  {Color.DIM}evidence:{Color.END}")
        for item in v.evidence:
            pts = f"+{item.points:>3}"
            attr = _truncate(item.attribution, 24).ljust(24)
            signal = _truncate(item.signal, self.width - 14 - 24 - 4)
            self.line(f"    {Color.OK}{pts}{Color.END}  "
                      f"{Color.BOLD}{attr}{Color.END} "
                      f"{Color.DIM}{signal}{Color.END}")

    def exposures(self) -> None:
        hits = [f for f in self.all if f.layer == "exposures" and f.status == "hit"]
        total = sum(1 for f in self.all if f.layer == "exposures")
        self.blank()
        self.line(f"{Color.BOLD}[EXPOSURES]{Color.END}  "
                  f"{Color.WARN if hits else Color.OK}{len(hits)}{Color.END} found "
                  f"{Color.DIM}/ {total} probed{Color.END}")


# ============================================================================
# Main
# ============================================================================

def get_term_width(override: int | None = None) -> int:
    if override:
        return override
    try:
        return shutil.get_terminal_size((100, 24)).columns
    except Exception:
        return 100


def _scan_target(target: str, layers: set[str], args, renderer: Renderer | None,
                 idx: int, total: int) -> tuple[dict, float]:
    """Run all selected layers against one target.

    Returns (per-target JSON dict, elapsed seconds). When `renderer` is None
    (JSON mode) nothing is printed for findings; otherwise findings stream.
    """
    base_input, _ = normalize(target)
    if args.no_follow:
        base = base_input
        host = urllib.parse.urlparse(base_input).hostname or base_input
        note = ""
    else:
        base, host, note = resolve_canonical(base_input)

    if renderer is not None:
        renderer.set_context(base, host)
        if total > 1:
            renderer.info(f"target  {Color.BOLD}[{idx}/{total}] {target}{Color.END}  "
                          f"{Color.DIM}→ {base}{Color.END}")
        else:
            renderer.info(f"target  {Color.BOLD}{target}{Color.END}  "
                          f"{Color.DIM}→ {base}{Color.END}")
        if note:
            renderer.info(note)
        renderer.info(f"layers  {', '.join(sorted(layers))}")
        renderer.blank()
        # Reset accumulator for this target so summaries don't cross-contaminate
        renderer.all = []

    findings: list[Finding] = []
    t0 = time.time()

    # Single execution path: parallel scan via the as_completed generators.
    # Findings stream to the renderer in actual arrival order. If the
    # renderer is animated, each line gets its dots-then-status when it
    # comes in — work and presentation are decoupled.
    if "readiness" in layers:
        for f in scan_readiness(base, host):
            findings.append(f)
            if renderer is not None:
                renderer.feed(f)
    if "exposures" in layers:
        for f in scan_exposures(base):
            findings.append(f)
            if renderer is not None:
                renderer.feed(f)
    if "fingerprint" in layers:
        for f in scan_fingerprint(base, host):
            findings.append(f)
            if renderer is not None:
                renderer.feed(f)

    elapsed = time.time() - t0

    out = {
        "target": target,
        "scanned_base": base,
        "scanned_host": host,
        "note": note,
        "elapsed_seconds": round(elapsed, 2),
        "findings": [asdict(f) for f in findings],
    }
    if not args.no_score and "readiness" in layers:
        out["score"] = asdict(compute_readiness_score(findings))
    if not args.no_verdict:
        out["vibecoding"] = asdict(compute_verdict(findings))

    if renderer is not None:
        renderer.summary(elapsed)
        if not args.no_verdict:
            renderer.verdict(compute_verdict(renderer.all))
        renderer.exposures()
        if not args.no_score and "readiness" in layers:
            renderer.score(compute_readiness_score(renderer.all))

    return out, elapsed


def _read_target_list(path: str) -> list[str]:
    """Read targets from a file or stdin (when path == '-'). Skip blanks and #-comments."""
    src = sys.stdin if path == "-" else open(path)
    try:
        out = []
        for line in src:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out
    finally:
        if path != "-":
            src.close()


def main() -> int:
    p = argparse.ArgumentParser(
        description="agent-readiness scanner + AI footprint recon")
    p.add_argument("target", nargs="*",
                   help="domain or URL (one or more positional args)")
    p.add_argument("-l", "--list", metavar="FILE",
                   help="read targets from FILE, one per line ('-' for stdin). "
                        "Lines starting with # are ignored.")
    p.add_argument("--json", action="store_true", help="JSON output (array when multi-host)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-follow", action="store_true", help="do not follow initial redirect")
    p.add_argument("--only", choices=("readiness", "exposures", "fingerprint"),
                   action="append", help="run only specific layers (repeatable)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show every check in exposures/fingerprint, not just hits")
    p.add_argument("--no-score", action="store_true", help="suppress the readiness score")
    p.add_argument("--no-verdict", action="store_true", help="suppress the vibecoding verdict")
    p.add_argument("--width", type=int, default=None, help="column width (default: auto)")
    p.add_argument("--plain", action="store_true",
                   help="disable per-line dot animation. Output still streams "
                        "in arrival order; just no animated rendering. Use for "
                        "scripting or piping.")
    p.add_argument("--dot-ms", type=int, default=18,
                   help="ms between each animated dot (default 18)")
    p.add_argument("--min-dots", type=int, default=3,
                   help="minimum dots per finding (default 3)")
    args = p.parse_args()

    if args.no_color or (not args.json and not sys.stdout.isatty()):
        disable_color()

    targets = list(args.target)
    if args.list:
        targets.extend(_read_target_list(args.list))
    if not targets:
        p.error("provide at least one target via positional argument or --list")

    layers = set(args.only or ["readiness", "exposures", "fingerprint"])

    if args.json:
        results = []
        total_elapsed = 0.0
        for i, t in enumerate(targets, 1):
            try:
                out, elapsed = _scan_target(t, layers, args, None, i, len(targets))
                results.append(out)
                total_elapsed += elapsed
            except SystemExit as e:
                results.append({"target": t, "error": str(e)})
        payload = (
            results[0] if len(targets) == 1 else
            {"targets": results, "elapsed_seconds": round(total_elapsed, 2)}
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    renderer = Renderer(width=get_term_width(args.width),
                        verbose=args.verbose,
                        animated=not args.plain,
                        dot_ms=args.dot_ms,
                        min_dots=args.min_dots)
    renderer.banner("v0.5")

    grand_t0 = time.time()
    for i, t in enumerate(targets, 1):
        if i > 1:
            renderer.separator()
        try:
            _scan_target(t, layers, args, renderer, i, len(targets))
        except SystemExit as e:
            renderer.info(f"{Color.FAIL}skipped {t}: {e}{Color.END}")
        except Exception as e:
            renderer.info(f"{Color.FAIL}error on {t}: {e}{Color.END}")
    grand_elapsed = time.time() - grand_t0

    if len(targets) > 1:
        renderer.blank()
        renderer.info(f"all scans completed: "
                      f"{Color.BOLD}{len(targets)} targets{Color.END} "
                      f"in {grand_elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
