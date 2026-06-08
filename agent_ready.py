#!/usr/bin/env python3
"""
agent_ready.py — Versión en consola de los controles de isitagentready.com.

Alineado con el comportamiento real del escáner de Cloudflare:
- Sigue el redirect inicial y escanea el host canónico (ej: openbash.com -> www.openbash.com).
- DNS-AID por DoH con SVCB/HTTPS/TXT en _index/_a2a/_mcp._agents.<host>.
- Web Bot Auth por /.well-known/http-message-signatures-directory.
- Auth.md (/auth.md con H1 "Auth.md").
- MCP, Agent Skills y ACP en los paths estándar.
- x402 por respuesta HTTP 402 en /, /api, /api/v1.
- MPP por x-payment-info en /openapi.json.
- Soft-404: 200 + text/html en un /.well-known/*.json => FAIL.

Uso:
    python3 agent_ready.py openbash.com
    python3 agent_ready.py https://example.com --no-color
    python3 agent_ready.py example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

UA = "isitagentready-cli/0.2 (+https://isitagentready.com)"
TIMEOUT = 10
DOH = "https://cloudflare-dns.com/dns-query"

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

# Prefijos DNS-AID que prueba Cloudflare
AID_PROTOCOLS = ["index", "a2a", "mcp"]
AID_TYPES = [("SVCB", 64), ("HTTPS", 65), ("TXT", 16)]


# ---------------------------- presentación ----------------------------

class Color:
    OK = "\033[32m"
    FAIL = "\033[31m"
    WARN = "\033[33m"
    INFO = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def disable_color() -> None:
    for k in ("OK", "FAIL", "WARN", "INFO", "DIM", "BOLD", "END"):
        setattr(Color, k, "")


@dataclass
class Result:
    name: str
    status: str  # "pass" | "fail" | "warn" | "info"
    detail: str = ""


@dataclass
class Category:
    name: str
    results: list[Result] = field(default_factory=list)


# ----------------------------- HTTP / DNS ------------------------------

def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    max_bytes: int = 256 * 1024,
) -> tuple[int | None, dict[str, str], bytes, str]:
    """Devuelve (status, headers_lower, body, final_url). status=None en error."""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, method=method, headers=hdrs)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            body = resp.read(max_bytes)
            h = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, h, body, resp.geturl()
    except urllib.error.HTTPError as e:
        body = e.read(max_bytes) if hasattr(e, "read") else b""
        h = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, h, body, url
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, ConnectionError) as e:
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


# --------------------------- utilidades --------------------------------

def normalize(target: str) -> tuple[str, str]:
    if "://" not in target:
        target = "https://" + target
    p = urllib.parse.urlparse(target)
    if not p.netloc:
        raise SystemExit(f"objetivo inválido: {target!r}")
    return f"{p.scheme}://{p.netloc}", p.hostname or p.netloc


def resolve_canonical(base: str) -> tuple[str, str, str]:
    """Sigue redirects de GET / y devuelve (base_final, host_final, nota)."""
    status, _, _, final = http_request(base + "/")
    if status is None or not final:
        return base, urllib.parse.urlparse(base).hostname or base, ""
    p = urllib.parse.urlparse(final)
    new_base = f"{p.scheme}://{p.netloc}"
    note = f"redirigido desde {base}" if new_base != base else ""
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


# ----------------------------- chequeos --------------------------------

def check_robots_txt(base: str, ctx: dict) -> Result:
    status, headers, body, _ = http_request(base + "/robots.txt")
    if status != 200 or not body:
        return Result("robots.txt", "fail", f"status {status}")
    ctype = (headers or {}).get("content-type", "")
    if "text/plain" not in ctype.lower():
        return Result("robots.txt", "warn", f"content-type inesperado: {ctype}")
    txt = body.decode("utf-8", errors="replace")
    ctx["robots_txt"] = txt
    ctx["robots_entries"] = parse_robots(txt)
    if not any(ua for ua, _, _ in ctx["robots_entries"]):
        return Result("robots.txt", "warn", "200 pero sin User-agent")
    return Result("robots.txt", "pass", f"200, {ctype.split(';')[0]}")


def check_sitemap(base: str, ctx: dict) -> Result:
    sitemaps = []
    for line in (ctx.get("robots_txt") or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    if not sitemaps:
        status, headers, body, _ = http_request(base + "/sitemap.xml")
        if status == 200 and body and (b"<urlset" in body or b"<sitemapindex" in body):
            return Result("Sitemap", "pass", "/sitemap.xml (no declarado en robots.txt)")
        return Result("Sitemap", "fail", "sin sitemap declarado ni /sitemap.xml válido")
    ok = []
    for url in sitemaps:
        status, headers, body, _ = http_request(url)
        if status == 200 and body and (b"<urlset" in body or b"<sitemapindex" in body):
            ok.append(url)
    if len(ok) == len(sitemaps):
        return Result("Sitemap", "pass", f"{len(ok)}/{len(sitemaps)} sitemap(s) válidos")
    if ok:
        return Result("Sitemap", "warn", f"solo {len(ok)}/{len(sitemaps)} accesibles")
    return Result("Sitemap", "fail", "sitemap(s) declarados pero ninguno accesible")


def check_link_headers(base: str, ctx: dict) -> Result:
    status, headers, _, _ = http_request(base + "/")
    if status is None:
        return Result("Link headers", "fail", "sin respuesta")
    link = (headers or {}).get("link", "")
    if link:
        rels = re.findall(r'rel="?([^",;]+)"?', link)
        return Result("Link headers", "pass", f"rels: {', '.join(rels) or '—'}")
    return Result("Link headers", "fail", "sin cabecera Link en la home")


def check_dns_aid(base: str, ctx: dict, hosts: list[str]) -> Result:
    """DoH SVCB/HTTPS/TXT en _<proto>._agents.<host>."""
    found = []
    dnssec_ok = False
    for host in hosts:
        for proto in AID_PROTOCOLS:
            name = f"_{proto}._agents.{host}"
            for tname, tcode in AID_TYPES:
                if tname == "TXT" and proto != "index":
                    continue  # Cloudflare solo prueba TXT en _index
                resp = doh(name, tcode)
                if not resp:
                    continue
                if resp.get("Answer"):
                    found.append(f"{tname} {name}")
                    if resp.get("AD") is True:
                        dnssec_ok = True
    if found and dnssec_ok:
        return Result("DNS-AID", "pass", f"{found[0]} (DNSSEC AD=true)")
    if found:
        return Result("DNS-AID", "warn", f"{found[0]} pero sin DNSSEC")
    return Result("DNS-AID", "fail", "sin registros DNS-AID")


def check_markdown(base: str, ctx: dict) -> Result:
    status, headers, _, _ = http_request(
        base + "/", headers={"Accept": "text/markdown"}
    )
    if status is None:
        return Result("Negociación Markdown", "fail", "sin respuesta")
    if status >= 400:
        return Result("Negociación Markdown", "fail", f"status {status} para Accept: text/markdown")
    ctype = (headers or {}).get("content-type", "").lower()
    if "markdown" in ctype:
        return Result("Negociación Markdown", "pass", f"Content-Type: {ctype}")
    return Result("Negociación Markdown", "fail", f"sirve {ctype or 'sin Content-Type'}")


def check_ai_bot_rules(base: str, ctx: dict) -> Result:
    entries = ctx.get("robots_entries") or []
    if not entries:
        return Result("Reglas de bots de IA", "fail", "robots.txt vacío o ausente")
    declared = {ua.lower() for ua, _, _ in entries}
    matches = [b for b in AI_BOTS if b.lower() in declared]
    if matches:
        return Result(
            "Reglas de bots de IA", "pass",
            f"{len(matches)} bots: {', '.join(matches[:6])}{'…' if len(matches) > 6 else ''}",
        )
    return Result("Reglas de bots de IA", "fail", "ninguna regla específica para bots de IA")


def check_content_signals(base: str, ctx: dict) -> Result:
    txt = ctx.get("robots_txt") or ""
    found = [s for s in CONTENT_SIGNALS if re.search(rf"content-signal\s*:\s*[^#\n]*\b{s}\b", txt, re.I)]
    if found:
        return Result("Content Signals", "pass", f"señales: {', '.join(found)}")
    return Result("Content Signals", "fail", "sin Content-Signal en robots.txt")


def check_web_bot_auth(base: str, ctx: dict) -> Result:
    path = "/.well-known/http-message-signatures-directory"
    status, headers, body, _ = http_request(base + path, headers={"Accept": "application/json"})
    if status is None:
        return Result("Web Bot Auth", "fail", "sin respuesta")
    if status != 200:
        return Result("Web Bot Auth", "fail", f"{path}: {status}")
    if is_html(headers, body):
        return Result("Web Bot Auth", "fail", f"{path}: soft-404 (HTML)")
    try:
        json.loads(body)
        return Result("Web Bot Auth", "pass", path)
    except Exception:
        return Result("Web Bot Auth", "warn", f"{path}: 200 pero no JSON")


def _well_known_json(name: str, base: str, paths: list[str], accept: str = "application/json") -> Result:
    last = "no encontrado"
    for path in paths:
        status, headers, body, _ = http_request(base + path, headers={"Accept": accept})
        if status is None:
            last = f"{path}: error de red"
            continue
        if status != 200:
            last = f"{path}: {status}"
            continue
        if is_html(headers, body):
            last = f"{path}: soft-404 (HTML)"
            continue
        try:
            json.loads(body)
            ctype = (headers or {}).get("content-type", "").split(";")[0]
            return Result(name, "pass", f"{path} ({ctype})")
        except Exception:
            last = f"{path}: 200 pero JSON inválido"
    return Result(name, "fail", last)


def check_api_catalog(base: str, ctx: dict) -> Result:
    return _well_known_json(
        "API Catalog", base, ["/.well-known/api-catalog"],
        accept="application/linkset+json, application/json",
    )


def check_oauth_discovery(base: str, ctx: dict) -> Result:
    return _well_known_json(
        "OAuth / OIDC discovery", base,
        ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"],
    )


def check_oauth_pr(base: str, ctx: dict) -> Result:
    r = _well_known_json("OAuth Protected Resource", base, ["/.well-known/oauth-protected-resource"])
    if r.status == "pass":
        return r
    # Fallback: WWW-Authenticate en la home indica el recurso protegido
    status, headers, _, _ = http_request(base + "/")
    if headers and headers.get("www-authenticate"):
        return Result("OAuth Protected Resource", "warn",
                      f"WWW-Authenticate presente: {headers['www-authenticate'][:60]}")
    return r


def check_auth_md(base: str, ctx: dict) -> Result:
    status, headers, body, _ = http_request(
        base + "/auth.md", headers={"Accept": "text/markdown, text/plain, */*"}
    )
    if status != 200 or not body:
        return Result("Auth.md", "fail", f"/auth.md: {status}")
    ctype = (headers or {}).get("content-type", "").lower()
    if "markdown" not in ctype and "plain" not in ctype:
        return Result("Auth.md", "fail", f"/auth.md: content-type {ctype}")
    txt = body.decode("utf-8", errors="replace")
    if re.search(r"^#\s*auth\.md\b", txt, re.I | re.M):
        return Result("Auth.md", "pass", "/auth.md con encabezado válido")
    return Result("Auth.md", "warn", "/auth.md existe pero sin H1 'Auth.md'")


def check_mcp(base: str, ctx: dict) -> Result:
    return _well_known_json(
        "MCP Server Card", base,
        [
            "/.well-known/mcp/server-card.json",
            "/.well-known/mcp/server-cards.json",
            "/.well-known/mcp.json",
        ],
    )


def check_agent_skills(base: str, ctx: dict) -> Result:
    return _well_known_json(
        "Agent Skills index", base, ["/.well-known/agent-skills/index.json"],
    )


def check_webmcp(base: str, ctx: dict) -> Result:
    # WebMCP requiere ejecutar JS y leer navigator.modelContext, no es probable por HTTP solo.
    return Result("WebMCP", "info", "requiere browser headless (no verificable solo por HTTP)")


def check_x402(base: str, ctx: dict) -> Result:
    """Cloudflare prueba /, /api, /api/v1 esperando un 402 Payment Required."""
    for path in ("/", "/api", "/api/v1"):
        status, _, _, _ = http_request(base + path)
        if status == 402:
            return Result("x402", "pass", f"{path} responde 402")
    return Result("x402", "fail", "ningún endpoint responde 402")


def check_mpp(base: str, ctx: dict) -> Result:
    status, headers, body, _ = http_request(base + "/openapi.json", headers={"Accept": "application/json"})
    if status != 200 or not body or is_html(headers, body):
        return Result("MPP", "fail", "/openapi.json ausente o HTML")
    try:
        spec = json.loads(body)
    except Exception:
        return Result("MPP", "fail", "/openapi.json no parseable")
    found = 0
    for path_item in (spec.get("paths") or {}).values():
        if not isinstance(path_item, dict):
            continue
        for op in path_item.values():
            if isinstance(op, dict) and "x-payment-info" in op:
                found += 1
    if found:
        return Result("MPP", "pass", f"{found} operación(es) con x-payment-info")
    return Result("MPP", "fail", "/openapi.json sin x-payment-info")


def check_ucp(base: str, ctx: dict) -> Result:
    return _well_known_json("UCP", base, ["/.well-known/ucp", "/.well-known/ucp.json"])


def check_acp(base: str, ctx: dict) -> Result:
    return _well_known_json("ACP", base, ["/.well-known/acp.json", "/.well-known/acp"])


# ------------------------------ runner ---------------------------------

ICONS = {
    "pass": ("\033[32m", "✓"),
    "fail": ("\033[31m", "✗"),
    "warn": ("\033[33m", "!"),
    "info": ("\033[36m", "i"),
}


def render(category: Category) -> None:
    print(f"\n{Color.BOLD}{category.name}{Color.END}")
    for r in category.results:
        color = {"pass": Color.OK, "fail": Color.FAIL, "warn": Color.WARN, "info": Color.INFO}[r.status]
        icon = {"pass": "✓", "fail": "✗", "warn": "!", "info": "i"}[r.status]
        print(f"  {color}{icon}{Color.END} {r.name:<32} {Color.DIM}{r.detail}{Color.END}")


def summary(cats: list[Category]) -> None:
    counts = {"pass": 0, "fail": 0, "warn": 0, "info": 0}
    for c in cats:
        for r in c.results:
            counts[r.status] = counts.get(r.status, 0) + 1
    scored = counts["pass"] + counts["fail"] + counts["warn"]
    score = (counts["pass"] + 0.5 * counts["warn"]) / scored * 100 if scored else 0
    print(
        f"\n{Color.BOLD}Resumen{Color.END}: "
        f"{Color.OK}{counts['pass']} pass{Color.END}, "
        f"{Color.WARN}{counts['warn']} warn{Color.END}, "
        f"{Color.FAIL}{counts['fail']} fail{Color.END}"
        f"{(f', {Color.INFO}' + str(counts['info']) + ' info' + Color.END) if counts['info'] else ''}"
        f"  — puntaje {score:.0f}/100"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Versión consola de isitagentready.com")
    parser.add_argument("target", help="dominio o URL (ej: openbash.com)")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-follow", action="store_true", help="no seguir redirect inicial")
    parser.add_argument("--json", action="store_true", help="salida JSON")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_color()

    base_input, host_input = normalize(args.target)
    if args.no_follow:
        base, host, note = base_input, host_input, ""
    else:
        base, host, note = resolve_canonical(base_input)

    print(f"{Color.BOLD}Analizando{Color.END} {base} {Color.DIM}(host: {host}){Color.END}")
    if note:
        print(f"  {Color.DIM}{note}{Color.END}")

    # DNS-AID: probar host canónico y, si difiere, el apex
    aid_hosts = [host]
    apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 2 else host
    if apex != host:
        aid_hosts.append(apex)

    ctx: dict = {}

    categories: list[tuple[str, list[Callable[[], Result]]]] = [
        ("Discoverability", [
            lambda: check_robots_txt(base, ctx),
            lambda: check_sitemap(base, ctx),
            lambda: check_link_headers(base, ctx),
            lambda: check_dns_aid(base, ctx, aid_hosts),
        ]),
        ("Content", [
            lambda: check_markdown(base, ctx),
        ]),
        ("Bot Access Control", [
            lambda: check_ai_bot_rules(base, ctx),
            lambda: check_content_signals(base, ctx),
            lambda: check_web_bot_auth(base, ctx),
        ]),
        ("API, Auth, MCP & Skill Discovery", [
            lambda: check_api_catalog(base, ctx),
            lambda: check_oauth_discovery(base, ctx),
            lambda: check_oauth_pr(base, ctx),
            lambda: check_auth_md(base, ctx),
            lambda: check_mcp(base, ctx),
            lambda: check_agent_skills(base, ctx),
            lambda: check_webmcp(base, ctx),
        ]),
        ("Commerce (opcional)", [
            lambda: check_x402(base, ctx),
            lambda: check_mpp(base, ctx),
            lambda: check_ucp(base, ctx),
            lambda: check_acp(base, ctx),
        ]),
    ]

    cats: list[Category] = []
    for cname, checks in categories:
        c = Category(cname)
        for fn in checks:
            try:
                c.results.append(fn())
            except Exception as e:
                c.results.append(Result(getattr(fn, "__name__", "check"), "fail", f"error: {e}"))
        cats.append(c)

    if args.json:
        out = {
            "target": args.target,
            "scanned_base": base,
            "scanned_host": host,
            "categories": [
                {"name": c.name, "checks": [r.__dict__ for r in c.results]} for c in cats
            ],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    for c in cats:
        render(c)
    summary(cats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
