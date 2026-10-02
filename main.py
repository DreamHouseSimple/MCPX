from __future__ import annotations

import os
import asyncio
import json
import logging
import re
import sys
import threading
import socket
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, HTTPServer
import httpx
import websockets
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP
from ddgs import DDGS

# =====================================================================
# CONFIGURATION: Reads your endpoint securely from Environment Secrets
# =====================================================================
# Supports one or more bridge endpoints. Provide a single URL, or multiple
# URLs separated by commas/semicolons/newlines (e.g.
# "wss://host-a/ws, wss://host-b/ws, wss://host-c/ws") to maintain several
# simultaneous, independently-reconnecting MCP bridge connections.
def _parse_endpoints(raw: str | None) -> list[str]:
    if not raw:
        return []
    parts = re.split(r"[,;\n]+", raw)
    return [p.strip() for p in parts if p.strip()]


MCP_BRIDGE_ENDPOINTS = _parse_endpoints(os.environ.get("MCP_BRIDGE_ENDPOINT"))
# Fixed source URL for the 'special_info' tool - a specific, pre-configured
# page/source set up by the operator (could be internal docs, a private feed,
# a particular news/discount page, etc.). Set this as a secret once you have
# the real URL; the tool returns a clear error if unset.
SPECIAL_INFO_URL = os.environ.get("SPECIAL_INFO_URL")

# Setup clean logging output
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("McpBridgeClient")

# Initialize the Unified MCP Instance
mcp = FastMCP("AdvancedUnifiedToolbox")

# =====================================================================
# RELIABILITY ENGINE
# Query expansion, dedup/domain-trust scoring, content scrubbing, and a
# multi-strategy ("kill chain") content extractor. Adapted from the
# agent-search project's reliability layer, trimmed down to remove its
# SearXNG / FastAPI / sqlite / WHOIS / browser dependencies so it runs as
# a self-contained part of this single-file bridge (MIT licensed source:
# https://github.com/ - see agent-search/LICENSE in the source project).
# =====================================================================

# ---- SSRF guard: blocked domains / suspicious TLDs / private IPs ----
BLOCKED_FETCH_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "v.gd", "short.io",
}
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz", ".work",
    ".click", ".loan", ".win", ".racing", ".review", ".stream", ".download", ".bid",
}


def _is_safe_url_syntax(url: str) -> tuple[bool, str | None]:
    """Fast, network-free part of the SSRF guard (scheme/hostname/blocklist/
    suspicious TLD only). Returns (False, None) if already rejected, or
    (True, hostname) if DNS resolution should be checked next."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, None
        hostname = parsed.hostname.lower()
        if hostname in ("localhost", "localhost.localdomain", "0.0.0.0"):
            return False, None
        for blocked in BLOCKED_FETCH_DOMAINS:
            if hostname == blocked or hostname.endswith("." + blocked):
                return False, None
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return False, None
        return True, hostname
    except Exception:
        return False, None


def _is_resolved_ip_safe(addrinfo) -> bool:
    """Given a getaddrinfo() result, reject it if any resolved address is
    private/loopback/link-local/reserved/multicast."""
    try:
        for info in addrinfo:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


def _is_safe_url(url: str) -> bool:
    """Full SSRF safety check (syntax + blocking DNS resolution). This does a
    real network call (socket.getaddrinfo), so only call it from code that's
    already off the event loop (e.g. inside asyncio.to_thread), such as
    merge_and_rank_hits when invoked from web_search's threaded search path.
    For anything running directly on the event loop, use
    _is_safe_url_async instead so DNS lookups can't stall the websocket
    bridge's ping/pong keepalive."""
    ok, hostname = _is_safe_url_syntax(url)
    if not ok:
        return False
    try:
        return _is_resolved_ip_safe(socket.getaddrinfo(hostname, None))
    except Exception:
        return False


async def _is_safe_url_async(url: str) -> bool:
    """Async-safe equivalent of _is_safe_url: does DNS resolution via the
    event loop's own (non-blocking) resolver instead of a raw blocking
    socket.getaddrinfo call. Use this from any coroutine that isn't already
    isolated in a worker thread."""
    ok, hostname = _is_safe_url_syntax(url)
    if not ok:
        return False
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(hostname, None)
        return _is_resolved_ip_safe(addrinfo)
    except Exception:
        return False


async def _safe_get(client: httpx.AsyncClient, url: str, *, max_redirects: int = 5, **kwargs) -> httpx.Response:
    """GET a URL while validating every redirect hop against the SSRF guard
    before following it (blocks DNS-rebinding / redirect-to-internal tricks)."""
    current_url = url
    kwargs.pop("follow_redirects", None)
    for _ in range(max_redirects + 1):
        if not await _is_safe_url_async(current_url):
            raise ValueError(f"Unsafe URL blocked: {current_url}")
        response = await client.get(current_url, follow_redirects=False, **kwargs)
        if not response.is_redirect:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        next_url = urljoin(str(response.url or current_url), location)
        if not await _is_safe_url_async(next_url):
            raise ValueError(f"Unsafe redirect blocked: {current_url} -> {next_url}")
        current_url = next_url
    raise ValueError(f"Too many redirects for URL: {url}")


# ---- Domain trust: allowlist + suspicious-TLD + typosquat (no WHOIS / no network) ----
ESTABLISHED_DOMAINS = {
    "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk", "npr.org", "nytimes.com",
    "washingtonpost.com", "wsj.com", "economist.com", "theguardian.com", "bloomberg.com",
    "wikipedia.org", "wikimedia.org", "github.com", "stackoverflow.com",
    "developer.mozilla.org", "docs.python.org", "arxiv.org", "nature.com", "science.org",
    "nasa.gov", "who.int", "un.org", "europa.eu",
}
KNOWN_BRANDS = [
    "google", "amazon", "microsoft", "apple", "facebook", "twitter", "github",
    "wikipedia", "reuters", "bloomberg", "nytimes", "cnn", "bbc", "paypal",
    "openai", "anthropic",
]


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _detect_lookalike(domain: str) -> str | None:
    """Return the brand name if `domain` looks like a typosquat of it."""
    base = domain.replace("www.", "").split(".")[0]
    base_clean = base.replace("-", "").replace("_", "")
    for brand in KNOWN_BRANDS:
        if base == brand or base_clean == brand:
            return None
        dist = min(_levenshtein(base, brand), _levenshtein(base_clean, brand))
        threshold = 1 if len(brand) <= 5 else 2
        if 0 < dist <= threshold:
            return brand
    return None


def _domain_trust_tier(url: str) -> tuple[str, float]:
    """Lightweight trust check (allowlist / TLD / typosquat). No WHOIS
    network call, so it stays fast and doesn't depend on the WHOIS protocol
    being reachable from the hosting environment. Returns (tier, score 0..1)."""
    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
    except Exception:
        return "unknown", 0.4
    if not hostname:
        return "unknown", 0.4
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return "suspicious", 0.0
    trusted_tlds = (".gov", ".edu", ".mil", ".int")
    lookalike = _detect_lookalike(hostname)
    if lookalike and not hostname.endswith(trusted_tlds):
        return "suspicious", 0.0
    if hostname in ESTABLISHED_DOMAINS or any(hostname.endswith("." + d) for d in ESTABLISHED_DOMAINS):
        return "established", 1.0
    if hostname.endswith(trusted_tlds):
        return "established", 0.9
    return "standard", 0.6


# ---- Dedup + authority scoring across merged search hits ----
DOMAIN_AUTHORITY = {
    "wikipedia.org": 0.3, "github.com": 0.25, "stackoverflow.com": 0.25,
    "arxiv.org": 0.3, "docs.python.org": 0.25, "developer.mozilla.org": 0.25,
    "medium.com": 0.05, "reddit.com": 0.0, "quora.com": -0.05,
}
TRACKING_PARAMS = {
    "fbclid", "gclid", "igshid", "mc_cid", "mc_eid", "msclkid", "ref", "ref_src",
    "utm_campaign", "utm_content", "utm_medium", "utm_source", "utm_term", "ved",
}


def _clean_result_url(url: str) -> str:
    """Strip common tracking parameters while preserving useful query params."""
    parsed = urlparse(url)
    if not parsed.query:
        return url
    params = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in TRACKING_PARAMS and not k.lower().startswith("utm_")
    ]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _normalize_for_dedup(url: str) -> str:
    parsed = urlparse(_clean_result_url(url))
    host = re.sub(r"^www\.", "", parsed.hostname or "")
    return f"{host}{parsed.path.rstrip('/')}"


def merge_and_rank_hits(hits_per_query: list[tuple[str, list[dict]]]) -> list[dict]:
    """Dedup search hits gathered across one or more queries, and rank them
    by (how many queries surfaced it) + domain authority + domain trust, so
    low-quality/duplicate links stop burning source slots.

    hits_per_query[0] is always the caller's primary/main query - entries
    found by it get an explicit score boost so any additional queries
    (supplied by the caller for broader coverage) can't outrank/drown out
    the results that matched the primary query."""
    merged: dict[str, dict] = {}
    for query_index, (_query, hits) in enumerate(hits_per_query):
        for rank, res in enumerate(hits):
            url = res.get("href") or res.get("url")
            if not url or not _is_safe_url(url):
                continue
            key = _normalize_for_dedup(url)
            tier, trust_score = _domain_trust_tier(url)
            entry = merged.get(key)
            if entry is None:
                entry = {
                    "url": _clean_result_url(url),
                    "title": res.get("title") or "Unknown Source",
                    "snippet": res.get("body") or res.get("snippet") or "",
                    "hits": 0,
                    "best_rank": rank,
                    "trust_tier": tier,
                    "trust_score": trust_score,
                    "from_primary_query": False,
                }
                merged[key] = entry
            entry["hits"] += 1
            entry["best_rank"] = min(entry["best_rank"], rank)
            if query_index == 0:
                entry["from_primary_query"] = True

    def _score(e: dict) -> float:
        host = (urlparse(e["url"]).hostname or "").removeprefix("www.")
        authority = DOMAIN_AUTHORITY.get(host, 0.0)
        primary_bonus = 3.0 if e["from_primary_query"] else 0.0
        return (e["hits"] * 2.0) + authority + e["trust_score"] + primary_bonus - (e["best_rank"] * 0.05)

    return sorted(merged.values(), key=_score, reverse=True)


# ---- Lightweight content scrubber (indirect prompt-injection mitigation) ----
# Fetched web content is untrusted input. Before handing it to the LLM, strip
# obvious attempts to override instructions or impersonate the system. This
# is a condensed subset of agent-search's scrubber.py (which runs 70+
# patterns); this covers the highest-value cases cheaply with regex only.
_INJECTION_PATTERNS = [
    re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I),
    re.compile(r"disregard (all |any )?(previous|prior|above)", re.I),
    re.compile(r"you are now (in |an? )?(developer|debug|dan|jailbreak) mode", re.I),
    re.compile(r"system\s*prompt\s*:", re.I),
    re.compile(r"\bnew instructions?\s*:", re.I),
    re.compile(r"reveal (your|the) (system prompt|instructions)", re.I),
    re.compile(r"act as (if you (were|are)|an?) (unrestricted|unfiltered|jailbroken)", re.I),
]


def _scrub_content(text: str) -> str:
    if not text:
        return text
    redactions = 0
    for pattern in _INJECTION_PATTERNS:
        text, count = pattern.subn("[redacted: possible prompt injection]", text)
        redactions += count
    if redactions:
        logger.info(f"Scrubber redacted {redactions} suspicious instruction-like pattern(s) from fetched content")
    return text


# ---- Multi-strategy content extraction ("kill chain") ----
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]
# Extra headers that accompany each User-Agent above, mimicking what a real
# browser actually sends on a top-level navigation (many simple bot filters
# check for these alongside the UA string). Googlebot deliberately gets none
# of these - real crawlers don't send sec-ch-ua/sec-fetch-* client hints, so
# adding them there would be a giveaway rather than camouflage.
BROWSER_EXTRA_HEADERS = [
    {
        "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {},  # Googlebot: no browser-only client hints
]
CONTENT_SELECTORS = [
    "main", "article", "[role=main]", ".content", "#content",
    ".post-content", ".entry-content", ".article-body", ".post-body",
]
GARBAGE_TAGS = ["script", "style", "nav", "footer", "header", "aside", "iframe", "noscript", "form"]
GARBAGE_CLASSES = [".sidebar", ".comments", ".related", ".advertisement", ".ad", ".cookie-banner", ".popup", ".modal"]
PAYWALL_SIGNALS = [
    "subscribe to read", "premium content", "paywall", "sign up to continue",
    "members only", "login to view", "create a free account", "unlock this article",
]
MIN_USEFUL_CHARS = 200
MAX_CONTENT_CHARS = 8_000
FETCH_TIMEOUT = 15.0
WAYBACK_TIMEOUT = 20.0
_MEDIUM_DOMAINS = {
    "medium.com", "towardsdatascience.com", "betterprogramming.pub",
    "levelup.gitconnected.com", "hackernoon.com",
}


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.")


def _is_medium(url: str) -> bool:
    host = _hostname(url)
    return host in _MEDIUM_DOMAINS or host.endswith(".medium.com")


def _is_paywalled(text: str) -> bool:
    if len(text) > 2000:
        return False
    lower = text.lower()
    return any(sig in lower for sig in PAYWALL_SIGNALS)


# Raw HTML is capped before handing it to BeautifulSoup. Even though parsing
# now runs in a worker thread (see below), an unbounded parse of a multi-MB
# page can still tie up that thread for a long time; capping keeps worst-case
# parse time predictable and bounds memory use for abnormally large/malicious
# pages.
MAX_RAW_HTML_CHARS = 2_000_000


def _clean_html(html_text: str) -> str | None:
    """CPU-bound HTML parsing. Always call this via asyncio.to_thread from
    async code - BeautifulSoup's html.parser is pure Python and can run long
    enough on large pages to starve the event loop, which stalls the
    websocket's ping/pong keepalive and causes spurious disconnects."""
    soup = BeautifulSoup(html_text[:MAX_RAW_HTML_CHARS], "html.parser")
    for tag in soup(GARBAGE_TAGS):
        tag.decompose()
    for selector in GARBAGE_CLASSES:
        for el in soup.select(selector):
            el.decompose()
    for selector in CONTENT_SELECTORS:
        el = soup.select_one(selector)
        if el:
            text = el.get_text(separator="\n", strip=True)
            if len(text) >= MIN_USEFUL_CHARS:
                return text[:MAX_CONTENT_CHARS]
    text = soup.get_text(separator="\n", strip=True)
    return text[:MAX_CONTENT_CHARS] if len(text) >= MIN_USEFUL_CHARS else None


async def _strategy_direct(client: httpx.AsyncClient, url: str, ua_index: int = 0, referer: str | None = None) -> str | None:
    index = ua_index % len(USER_AGENTS)
    headers = {
        "User-Agent": USER_AGENTS[index],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        **BROWSER_EXTRA_HEADERS[index],
    }
    if referer:
        headers["Referer"] = referer
    try:
        r = await _safe_get(client, url, timeout=FETCH_TIMEOUT, headers=headers)
        if r.status_code in (403, 429) or not r.is_success:
            return None
        if "pdf" in r.headers.get("content-type", "").lower():
            return None
        text = await asyncio.to_thread(_clean_html, r.text)
        if text and not _is_paywalled(text):
            return text
        return None
    except Exception as exc:
        logger.debug(f"Direct fetch failed for {_hostname(url)}: {exc}")
        return None


def _readability_extract(html_text: str) -> str | None:
    """CPU-bound readability scoring. Always call via asyncio.to_thread (see
    _clean_html's docstring for why)."""
    soup = BeautifulSoup(html_text[:MAX_RAW_HTML_CHARS], "html.parser")
    for tag in soup(GARBAGE_TAGS):
        tag.decompose()
    candidates = []
    for tag in soup.find_all(["div", "article", "section", "main"]):
        text = tag.get_text(strip=True)
        if len(text) < MIN_USEFUL_CHARS:
            continue
        p_count = len(tag.find_all("p"))
        link_density = len(tag.find_all("a")) / max(p_count, 1)
        score = len(text) + (p_count * 100) - (link_density * 200)
        candidates.append((score, text))
    if candidates:
        candidates.sort(key=lambda c: c[0], reverse=True)
        text = candidates[0][1]
        if not _is_paywalled(text):
            return text[:MAX_CONTENT_CHARS]
    return None


async def _strategy_readability(client: httpx.AsyncClient, url: str) -> str | None:
    """Readability-style extraction: score HTML blocks by paragraph density
    vs link density instead of relying on fixed CSS selectors."""
    try:
        r = await _safe_get(client, url, timeout=FETCH_TIMEOUT, headers={"User-Agent": USER_AGENTS[0]})
        if not r.is_success:
            return None
        return await asyncio.to_thread(_readability_extract, r.text)
    except Exception as exc:
        logger.debug(f"Readability fetch failed for {_hostname(url)}: {exc}")
        return None


async def _strategy_wayback(client: httpx.AsyncClient, url: str) -> str | None:
    """Fall back to the latest Wayback Machine snapshot for dead/blocked pages."""
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": url, "output": "json", "limit": "1", "sort": "reverse"},
            timeout=FETCH_TIMEOUT,
        )
        if r.is_success:
            data = r.json()
            if len(data) > 1:
                timestamp = data[1][1]
                snapshot_url = f"https://web.archive.org/web/{timestamp}/{url}"
                r2 = await _safe_get(client, snapshot_url, timeout=WAYBACK_TIMEOUT, headers={"User-Agent": USER_AGENTS[0]})
                if r2.is_success:
                    text = await asyncio.to_thread(_clean_html, r2.text)
                    if text:
                        return text
        return None
    except Exception as exc:
        logger.debug(f"Wayback fetch failed for {_hostname(url)}: {exc}")
        return None


async def _strategy_medium_bypass(client: httpx.AsyncClient, url: str) -> str | None:
    """Medium paywalls most articles; the Freedium mirror renders the full
    article text without the paywall. Falls through to other strategies on
    failure."""
    try:
        freedium_url = f"https://freedium.cfd/{url}"
        r = await _safe_get(client, freedium_url, timeout=FETCH_TIMEOUT, headers={"User-Agent": USER_AGENTS[0]})
        if r.is_success:
            return await asyncio.to_thread(_clean_html, r.text)
        return None
    except Exception as exc:
        logger.debug(f"Medium bypass failed for {_hostname(url)}: {exc}")
        return None


# ---- Last-resort headless browser fallback (Playwright) ----
# Only used when every lightweight HTTP-based strategy above has failed.
# Real bot-protection (Cloudflare/Akamai-style JS challenges, TLS/header
# fingerprinting) generally can't be defeated with plain HTTP requests no
# matter how browser-like the headers look - it needs an actual browser
# engine executing JavaScript. This is deliberately gated as a last resort
# since launching/driving Chromium is far heavier (memory, CPU, latency)
# than the HTTP-based strategies.
HEADLESS_NAV_TIMEOUT = 20_000  # milliseconds
HEADLESS_SETTLE_DELAY = 2.5    # seconds to let JS challenges/redirects resolve
_headless_browser = None
_headless_browser_lock = asyncio.Lock()
# Bounds how many headless pages can be open at once, since each Chromium
# tab costs real memory/CPU - keep this low on constrained hosts (e.g. free
# hosting tiers) to avoid the process getting OOM-killed.
_headless_semaphore = asyncio.Semaphore(1)


async def _get_headless_browser():
    global _headless_browser
    if _headless_browser is None:
        async with _headless_browser_lock:
            if _headless_browser is None:
                from playwright.async_api import async_playwright
                playwright_ctx = await async_playwright().start()
                _headless_browser = await playwright_ctx.chromium.launch(
                    headless=True,
                    args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
                )
    return _headless_browser


async def _strategy_headless_browser(url: str) -> str | None:
    try:
        browser = await _get_headless_browser()
    except Exception as exc:
        logger.debug(f"Headless browser unavailable (is Playwright/Chromium installed?): {exc}")
        return None

    async with _headless_semaphore:
        context = None
        try:
            context = await browser.new_context(
                user_agent=USER_AGENTS[0],
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=HEADLESS_NAV_TIMEOUT)
            # Give Cloudflare/Akamai-style JS challenges a moment to resolve
            # and redirect to the real page before we read the DOM.
            await asyncio.sleep(HEADLESS_SETTLE_DELAY)
            html_text = await page.content()
            text = await asyncio.to_thread(_clean_html, html_text)
            if text and not _is_paywalled(text):
                return text
            return None
        except Exception as exc:
            logger.debug(f"Headless browser fetch failed for {_hostname(url)}: {exc}")
            return None
        finally:
            if context is not None:
                await context.close()


@dataclass
class ExtractResult:
    url: str
    content: str | None
    strategy: str | None
    trust_tier: str


async def extract_content(client: httpx.AsyncClient, url: str, *, allow_headless: bool = True) -> ExtractResult:
    """Escalating content extraction: tries several strategies (cheap/fast
    first) until one returns usable content, instead of giving up after one
    attempt. Adapted from agent-search's kill_chain(), trimmed to the
    strategies that don't need SearXNG or WHOIS. A headless-browser pass is
    included as the final, most expensive fallback, unless allow_headless is
    False (used by callers like deep_research that fan out across many URLs
    under a shared time budget, where one slow headless attempt shouldn't
    eat the whole budget)."""
    tier, _ = _domain_trust_tier(url)
    if not await _is_safe_url_async(url):
        return ExtractResult(url=url, content=None, strategy=None, trust_tier=tier)

    attempts: list[tuple[str, object]] = []
    if _is_medium(url):
        attempts.append(("medium-bypass", lambda: _strategy_medium_bypass(client, url)))
    attempts.append(("direct", lambda: _strategy_direct(client, url)))
    attempts.append(("googlebot-ua", lambda: _strategy_direct(client, url, ua_index=3, referer="https://www.google.com/")))
    attempts.append(("readability", lambda: _strategy_readability(client, url)))
    attempts.append(("wayback", lambda: _strategy_wayback(client, url)))
    if allow_headless:
        attempts.append(("headless-browser", lambda: _strategy_headless_browser(url)))

    for name, factory in attempts:
        try:
            content = await factory()
        except Exception as exc:
            logger.debug(f"Strategy '{name}' raised for {_hostname(url)}: {exc}")
            content = None
        if content:
            return ExtractResult(url=url, content=_scrub_content(content), strategy=name, trust_tier=tier)

    return ExtractResult(url=url, content=None, strategy=None, trust_tier=tier)


# ---- Shared async HTTP client for content extraction ----
_http_client: httpx.AsyncClient | None = None
_http_client_lock = asyncio.Lock()


async def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        async with _http_client_lock:
            if _http_client is None:
                _http_client = httpx.AsyncClient(
                    headers={"Accept-Encoding": "gzip, deflate"},
                    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                    http2=True,
                )
    return _http_client


# =====================================================================
# TOOL CATEGORY 1: QUICK WEB SEARCH
# =====================================================================
@mcp.tool()
async def web_search(query: str, max_results: int = 5) -> str:
    """
    Performs a quick web search and returns short result snippets (title, URL,
    summary) without visiting or scraping any pages. Use this for simple,
    fast lookups such as current prices, scores, quick facts, or definitions.
    Searches exactly the query you provide, unmodified - this tool does not
    reformulate, expand, or otherwise alter your wording, so phrase `query`
    the way you'd want it typed into a search engine. If you get no/poor
    results, call again yourself with a different phrasing rather than
    relying on this tool to guess one. For in-depth topics that need
    multi-source analysis and full-page content, use 'deep_research' instead.
    """
    capped = max(1, min(max_results, 10))

    def _search_once(q: str) -> list[dict]:
        try:
            with DDGS() as ddgs:
                # backend="auto" tries multiple search engines (bing, brave,
                # duckduckgo, google, etc.) with automatic fallback if one is
                # rate-limited or temporarily blocked.
                return ddgs.text(q, max_results=max(capped, 8), backend="auto") or []
        except Exception as e:
            logger.warning(f"web_search query failed for '{q}': {e}")
            return []

    def _run_search() -> str:
        logger.info(f"Performing quick web search for: {query}")
        hits_per_query = [(query, _search_once(query))]

        ranked = merge_and_rank_hits(hits_per_query)
        if not ranked:
            return f"No web search results found for: '{query}'."

        lines = [f"--- Web Search Results for: {query} ---"]
        for index, res in enumerate(ranked[:capped], 1):
            tag = " [low-trust domain]" if res["trust_tier"] == "suspicious" else ""
            lines.append(f"{index}. {res['title']}{tag}\n   URL: {res['url']}\n   {res['snippet']}")
        return "\n".join(lines)

    # Run the blocking network call in a worker thread so it can never stall
    # the websocket bridge's event loop (and its ping/pong keepalive).
    return await asyncio.to_thread(_run_search)

# =====================================================================
# TOOL CATEGORY 2: DEEP RESEARCH & THINKING AGENT
# =====================================================================
@mcp.tool()
async def deep_research(topic: str, queries: list[str] | None = None) -> str:
    """
    Performs full deep research for topics that genuinely require it (e.g.
    in-depth explanations, comparisons, analysis, or open-ended questions).
    Searches the live web, deduplicates and ranks the combined candidates by
    relevance/domain trust, then extracts full-page content from the best
    sources using an escalating multi-strategy fetcher (direct fetch,
    readability scoring, UA rotation, Wayback Machine, and paywall/Medium
    bypasses) before synthesizing a deep response. This is slower than
    'web_search' (it fetches full pages), so do NOT use it for simple
    quick-fact lookups (e.g. current prices, scores, dates) — use
    'web_search' for those instead.

    `topic` is searched exactly as given - it is never reformulated,
    expanded, or otherwise altered. If you want broader multi-angle
    coverage (different phrasings, sub-questions, related angles, etc.),
    pass them explicitly via `queries` (each run as its own search, same as
    `topic`) rather than relying on this tool to invent them - you (the
    model) own the decision of what to search for, since you understand the
    user's actual intent far better than a keyword heuristic can. Only the
    first 4 entries of `queries` are used.
    """
    TARGET_SOURCES = 4            # how many good sources we want in the final report
    CANDIDATE_POOL_PER_QUERY = 6  # search hits to pull per query
    MAX_EXTRACTION_ATTEMPTS = 10  # how many ranked candidates to try extracting
    EXTRACTION_CONCURRENCY = 4    # concurrent page fetches
    MAX_ADDITIONAL_QUERIES = 4    # cap on caller-supplied extra queries, to protect SEARCH_BUDGET
    SEARCH_BUDGET = 15            # overall cap for the whole search phase (all queries)
    RANK_BUDGET = 10              # overall cap for dedup/trust ranking (DNS-resolving safety checks)
    EXTRACTION_TIMEOUT = 30       # overall cap so the tool call can't hang
    # With the budgets above, worst case is ~55s total - comfortably under
    # the ~60-120s tool-call timeouts most MCP clients/relays enforce, so
    # the tool reliably returns *something* instead of silently timing out.

    start_time = asyncio.get_event_loop().time()

    def _search_one(q: str) -> list[dict]:
        try:
            with DDGS(timeout=10) as ddgs:
                return ddgs.text(q, max_results=CANDIDATE_POOL_PER_QUERY, backend="auto") or []
        except Exception as e:
            logger.warning(f"deep_research query failed for '{q}': {e}")
            return []

    logger.info(f"Initiating deep multi-source research for: {topic}")

    # `topic` plus whatever additional queries the caller explicitly
    # supplied (never auto-generated). Each runs concurrently in its own
    # worker thread (instead of one after another) so N queries cost
    # roughly one query's latency instead of N times it, and an overall
    # SEARCH_BUDGET caps worst-case wall-clock time even if DDGS itself
    # runs long. Deduplicated (preserving order) so a caller accidentally
    # repeating `topic` inside `queries` doesn't spawn a wasted duplicate
    # search task.
    seen_queries: set[str] = set()
    all_queries: list[str] = []
    for q in [topic] + list(queries or [])[:MAX_ADDITIONAL_QUERIES]:
        if q not in seen_queries:
            seen_queries.add(q)
            all_queries.append(q)
    search_tasks = {q: asyncio.create_task(asyncio.to_thread(_search_one, q)) for q in all_queries}
    done, pending = await asyncio.wait(search_tasks.values(), timeout=SEARCH_BUDGET)
    if pending:
        logger.warning(
            f"deep_research search phase timed out for {len(pending)} of "
            f"{len(all_queries)} quer{'y' if len(pending) == 1 else 'ies'} on '{topic}'"
        )
        for t in pending:
            t.cancel()
    hits_per_query = []
    for q, task in search_tasks.items():
        try:
            hits_per_query.append((q, task.result() if task in done else []))
        except Exception:
            hits_per_query.append((q, []))

    # Dedup + rank by domain trust/authority. This calls the blocking
    # (DNS-resolving) _is_safe_url for every hit, so it still runs off the
    # event loop - but now under its own budget too, since a slow/hanging
    # DNS lookup shouldn't be able to stall the whole tool call.
    try:
        ranked = await asyncio.wait_for(asyncio.to_thread(merge_and_rank_hits, hits_per_query), timeout=RANK_BUDGET)
    except asyncio.TimeoutError:
        logger.warning(f"deep_research ranking phase timed out for '{topic}'; using unranked, deduplicated hits")
        # Cheap, DNS-free fallback: dedup by normalized URL only, skipping
        # the trust/safety scoring. This only affects result ordering, not
        # safety - extract_content() independently re-validates every URL
        # (SSRF guard) before fetching anything from it.
        seen: set[str] = set()
        ranked = []
        for _q, hits in hits_per_query:
            for res in hits:
                url = res.get("href") or res.get("url")
                if not url:
                    continue
                key = _normalize_for_dedup(url)
                if key in seen:
                    continue
                seen.add(key)
                ranked.append({
                    "url": _clean_result_url(url),
                    "title": res.get("title") or "Unknown Source",
                    "snippet": res.get("body") or res.get("snippet") or "",
                    "hits": 1,
                    "best_rank": 0,
                    "trust_tier": "unknown",
                    "trust_score": 0.4,
                })
    if not ranked:
        return f"Deep research failed: No search results found for '{topic}'."

    # Prefer trustworthy, deduplicated candidates; keep a larger pool than
    # TARGET_SOURCES so individual extraction failures don't shrink the report.
    candidates = [r for r in ranked if r["trust_tier"] != "suspicious"][:MAX_EXTRACTION_ATTEMPTS]
    if not candidates:
        candidates = ranked[:MAX_EXTRACTION_ATTEMPTS]

    client = await _get_http_client()
    semaphore = asyncio.Semaphore(EXTRACTION_CONCURRENCY)

    async def _extract_one(cand: dict) -> tuple[dict, ExtractResult]:
        async with semaphore:
            # allow_headless=False: deep_research fans out across many
            # candidate URLs under a shared time budget, so the slowest
            # fallback strategy (headless browser) is reserved for
            # single-URL tools like special_info instead.
            result = await extract_content(client, cand["url"], allow_headless=False)
            return cand, result

    def _fallback_result(cand: dict) -> tuple[dict, ExtractResult]:
        # content=None here means the compiled_knowledge loop below falls
        # back to the search snippet for this candidate instead of losing
        # the source entirely.
        return cand, ExtractResult(url=cand["url"], content=None, strategy=None, trust_tier=cand["trust_tier"])

    try:
        tasks = [asyncio.create_task(_extract_one(c)) for c in candidates]
        done, pending = await asyncio.wait(tasks, timeout=EXTRACTION_TIMEOUT)
        for task in pending:
            task.cancel()
        extraction_results = []
        for cand, task in zip(candidates, tasks):
            if task in done:
                try:
                    extraction_results.append(task.result())
                except Exception as e:
                    logger.debug(f"Extraction failed for {cand['url']}: {e}")
                    extraction_results.append(_fallback_result(cand))
            else:
                extraction_results.append(_fallback_result(cand))
        if pending:
            logger.warning(
                f"deep_research extraction timed out for {len(pending)} of "
                f"{len(candidates)} candidate(s) on '{topic}'; using snippets for those"
            )
    except Exception as e:
        logger.exception("deep_research extraction failed")
        return f"Error executing deep research module: {str(e)}"

    compiled_knowledge = []
    for cand, result in extraction_results:
        if len(compiled_knowledge) >= TARGET_SOURCES:
            break

        body_text = result.content
        strategy = result.strategy or "snippet-fallback"
        if not body_text:
            # Full-page extraction failed on every strategy (blocked,
            # JS-only page, timeout, etc.) - fall back to the search
            # snippet rather than losing the source entirely.
            body_text = cand["snippet"]
            strategy = "snippet-fallback"
        if not body_text:
            continue  # nothing usable at all from this source

        body_text = body_text[:2500]
        tag = f" [{result.trust_tier}, via {strategy}]"
        compiled_knowledge.append(
            f"### SOURCE {len(compiled_knowledge) + 1}: {cand['title']}{tag}\nURL: {cand['url']}\nDEEP MATERIAL:\n{body_text}\n"
        )

    if not compiled_knowledge:
        return (
            f"Deep research failed: none of the {len(candidates)} candidate "
            f"sources for '{topic}' could be safely accessed or scraped."
        )

    elapsed = asyncio.get_event_loop().time() - start_time
    logger.info(f"deep_research completed for '{topic}' in {elapsed:.1f}s with {len(compiled_knowledge)} source(s)")

    report_header = f"=== DEEP RESEARCH REPORT GENERATED FOR: {topic.upper()} ===\n"
    return report_header + "\n".join(compiled_knowledge)

# =====================================================================
# TOOL CATEGORY 3: SPECIAL INFO SOURCE
# =====================================================================
@mcp.tool()
async def special_info() -> str:
    """
    Fetches content from ONE specific, pre-configured info source (set up by
    the operator ahead of time - e.g. a particular news/docs/discount page,
    an internal resource, or any other fixed URL), and returns its full
    current page content. Uses the same escalating multi-strategy fetcher as
    'deep_research' (direct fetch, readability scoring, UA rotation, Wayback
    Machine fallback), so a temporary block or dead link is less likely to
    come back empty.

    This is NOT a general web search and does NOT accept a topic/query - it
    always reads the exact same configured source regardless of what the
    user asks about. Only call this when the user's request specifically
    matches what that configured source is for (the operator's system
    prompt/instructions should describe what it is here); for any other
    topic, question, or general lookup, use 'web_search' or 'deep_research'
    instead.
    """
    MAX_CHARS = 300_000  # safety cap - stays well under websockets' ~1MB default message limit

    if not SPECIAL_INFO_URL:
        return "Error: SPECIAL_INFO_URL is not configured in Secrets yet."
    if not _is_safe_url(SPECIAL_INFO_URL):
        return "Error: SPECIAL_INFO_URL is not a safe/valid http(s) URL."

    client = await _get_http_client()
    try:
        # 95s budget: the kill chain now ends with a headless-browser
        # fallback (page navigation + settle delay) which takes longer than
        # the plain HTTP strategies that precede it. Raised from 60s since
        # the worst-case cumulative duration of all strategies combined
        # (direct/googlebot/readability/wayback/headless, each slow-but-not
        # -fast-failing) can exceed ~100s, which left the headless fallback
        # without a fair chance to run before the outer timeout fired.
        result = await asyncio.wait_for(extract_content(client, SPECIAL_INFO_URL), timeout=95)
    except asyncio.TimeoutError:
        return "Error fetching special info: request timed out."
    except Exception as e:
        return f"Error fetching special info: {str(e)}"

    body_text = result.content
    if not body_text:
        return (
            "Special info fetch returned no readable content after trying "
            "multiple extraction strategies (direct fetch, UA rotation, "
            "readability scoring, Wayback Machine). The page may require "
            "JavaScript rendering, which this tool cannot execute."
        )

    truncated = len(body_text) > MAX_CHARS
    body_text = body_text[:MAX_CHARS]
    header = f"=== SPECIAL INFO ({datetime.now().strftime('%Y-%m-%d')}) ==="
    if result.trust_tier == "suspicious":
        header += " [low-trust domain]"
    if truncated:
        header += " [TRUNCATED - page exceeded size limit]"
    return f"{header}\n{body_text}"

# =====================================================================
# CORE PIPELINE & HOSTING BRIDGE (Koyeb compatible)
# =====================================================================
async def list_available_tools():
    """Returns tool metadata using the public FastMCP API when available,
    falling back to older internal storage for compatibility."""
    if hasattr(mcp, "list_tools"):
        tools = await mcp.list_tools()
        return [
            {
                "name": t.name,
                "description": getattr(t, "description", "") or "",
                "inputSchema": getattr(t, "inputSchema", None) or getattr(t, "input_schema", {}) or {}
            }
            for t in tools
        ]
    # Legacy fallback for older FastMCP versions without list_tools()
    return [
        {
            "name": t.name,
            "description": getattr(t, "description", "") or "",
            "inputSchema": getattr(t, "input_schema", None) or getattr(t, "inputSchema", {}) or {}
        }
        for t in mcp._tools.values()
    ]

async def execute_tool(tool_name: str, tool_args: dict):
    """Executes a registered tool by name, preferring the public FastMCP
    call_tool API (which validates arguments and offloads sync functions off
    the event loop). Falls back to legacy internal dict access for older SDK
    versions, running the sync tool function in a worker thread so a slow
    tool (e.g. deep_research) can't stall the websocket's ping/pong."""
    if hasattr(mcp, "call_tool"):
        try:
            return await mcp.call_tool(tool_name, tool_args)
        except Exception as e:
            if "not found" in str(e).lower() or "unknown tool" in str(e).lower():
                raise LookupError(f"Tool {tool_name} not found") from e
            raise

    if tool_name not in mcp._tools:
        raise LookupError(f"Tool {tool_name} not found")
    tool_fn = mcp._tools[tool_name]
    if asyncio.iscoroutinefunction(tool_fn):
        return await tool_fn(**tool_args)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: tool_fn(**tool_args))

def _extract_text(result) -> str:
    """Normalizes whatever shape call_tool/legacy invocation returns into text."""
    # Newer SDKs may wrap results in an object exposing a `.content` list
    # (e.g. CallToolResult) rather than returning the list directly.
    content = getattr(result, "content", None)
    items = content if content is not None else result

    if isinstance(items, (list, tuple)):
        parts = []
        for item in items:
            text = getattr(item, "text", None)
            parts.append(text if text is not None else str(item))
        return "\n".join(parts)
    return str(items)


# How often to send an application-level heartbeat over each connection. Some
# intermediary proxies/load balancers (seen on certain free-tier hosts) only
# treat actual data frames as "activity" and ignore low-level WebSocket
# ping/pong control frames, recycling connections that look idle to them even
# though this script's own ping/pong keepalive is working fine. Sending a
# real (tiny) message periodically covers that case. This is a JSON-RPC
# notification (no "id"), so per spec it never expects or receives a reply -
# safe even if the remote side doesn't recognize the method.
HEARTBEAT_INTERVAL = 25


async def _heartbeat_loop(websocket, tag: str = ""):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await websocket.send(json.dumps({"jsonrpc": "2.0", "method": "notifications/heartbeat"}))
    except asyncio.CancelledError:
        raise
    except websockets.ConnectionClosed:
        pass
    except Exception as exc:
        logger.debug(f"{tag}Heartbeat send failed: {exc}")


async def run_mcp_bridge(endpoint_url: str, label: str | None = None):
    tag = f"[{label}] " if label else ""
    logger.info(f"{tag}Connecting directly to remote MCP Bridge Endpoint ({endpoint_url})...")
    while True:
        try:
            async for websocket in websockets.connect(endpoint_url, ping_interval=20, ping_timeout=30):
                heartbeat_task = asyncio.create_task(_heartbeat_loop(websocket, tag))
                try:
                    logger.info(f"{tag}Successfully connected to the remote cloud server!")
                    async for message in websocket:
                        # Each message is handled in its own try/except so a
                        # single malformed/unexpected message (bad JSON, a
                        # bug in a handler, etc.) can't take down the whole
                        # connection and trigger an unnecessary reconnect -
                        # only a genuine ConnectionClosed should do that.
                        try:
                            request = json.loads(message)
                            method = request.get("method")
                            req_id = request.get("id")

                            if method == "initialize":
                                params = request.get("params", {})
                                response = {"jsonrpc": "2.0","id": req_id,"result": {"protocolVersion": params.get("protocolVersion", "2024-11-05"),"capabilities": {"tools": {"listChanged": False}},"serverInfo": {"name": "AdvancedUnifiedToolbox","version": "1.0.0"}}}
                                await websocket.send(json.dumps(response))
                                logger.info("MCP initialize handshake completed.")
                            elif method == "notifications/initialized":
                                logger.info("MCP client initialization completed.")
                            elif method == "tools/list":
                                try:
                                    tools_list = await list_available_tools()
                                    response = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}}
                                except Exception as e:
                                    logger.exception("Failed to list tools")
                                    response = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}}
                                await websocket.send(json.dumps(response))
                                logger.info("Synchronized structural multi-tool suite definitions.")
                            elif method == "tools/call":
                                params = request.get("params", {})
                                tool_name = params.get("name")
                                tool_args = params.get("arguments", {})

                                logger.info(f"Execution requested for tool: {tool_name} with args: {tool_args}")

                                try:
                                    result = await execute_tool(tool_name, tool_args)
                                    response = {
                                        "jsonrpc": "2.0",
                                        "id": req_id,
                                        "result": {
                                            "content": [{"type": "text", "text": _extract_text(result)}]
                                        }
                                    }
                                except LookupError as e:
                                    response = {
                                        "jsonrpc": "2.0",
                                        "id": req_id,
                                        "error": {"code": -32601, "message": str(e)}
                                    }
                                except Exception as e:
                                    logger.exception(f"Tool execution failed for '{tool_name}'")
                                    response = {
                                        "jsonrpc": "2.0",
                                        "id": req_id,
                                        "error": {"code": -32603, "message": str(e)}
                                    }

                                await websocket.send(json.dumps(response))
                                logger.info(f"Returned execution results for '{tool_name}'.")
                        except websockets.ConnectionClosed:
                            raise
                        except Exception as e:
                            logger.warning(f"{tag}Failed to process an incoming message, skipping it: {e}")

                except websockets.ConnectionClosed as e:
                    code = getattr(e, "code", None)
                    reason = getattr(e, "reason", None) or "(no reason given)"
                    origin = "server" if getattr(e, "rcvd", None) else "client/network"
                    logger.warning(
                        f"{tag}Connection lost inside session "
                        f"(close_code={code}, reason={reason!r}, closed_by={origin}). "
                        f"Attempting to reconnect..."
                    )
                except Exception as e:
                    logger.error(f"{tag}Internal processing loop error occurred: {e}")
                finally:
                    heartbeat_task.cancel()

        except Exception as e:
            logger.error(f"{tag}Failed to connect or connection lost completely: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)

def run_health_check_server():
    """Starts a minimal HTTP server to satisfy Hugging Face and allow pinging."""
    class HealthCheckHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            return

    # Port Dynamic
    port = int(os.environ.get("PORT", 10000))
    server = HTTPServer(("0.0.0.0", port), HealthCheckHandler)

    logger.info(f"Health check server started on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    if not MCP_BRIDGE_ENDPOINTS:
        logger.error("Error: MCP_BRIDGE_ENDPOINT variable not found in Secrets configuration!")
        sys.exit(1)

    logger.info(f"Configured {len(MCP_BRIDGE_ENDPOINTS)} MCP Bridge Endpoint(s).")

    # Start the HTTP server in a separate background thread so it doesn't block the WebSocket bridge
    threading.Thread(target=run_health_check_server, daemon=True).start()

    async def _run_all_bridges():
        # Each endpoint gets its own independent, self-reconnecting websocket
        # connection running concurrently, so one endpoint dropping doesn't
        # affect the others. run_mcp_bridge() already retries forever
        # internally and shouldn't normally raise, but return_exceptions=True
        # ensures that even if something truly unexpected escapes one
        # endpoint's task, asyncio.gather() won't cancel the other sibling
        # connections to enforce that isolation guarantee end-to-end.
        labels = (
            [None] if len(MCP_BRIDGE_ENDPOINTS) == 1
            else [f"conn-{i + 1}" for i in range(len(MCP_BRIDGE_ENDPOINTS))]
        )
        results = await asyncio.gather(
            *(run_mcp_bridge(ep, label) for ep, label in zip(MCP_BRIDGE_ENDPOINTS, labels)),
            return_exceptions=True,
        )
        for (ep, label), result in zip(zip(MCP_BRIDGE_ENDPOINTS, labels), results):
            if isinstance(result, Exception):
                tag = f"[{label}] " if label else ""
                logger.error(f"{tag}Bridge task for {ep} exited unexpectedly: {result}")

    try:
        asyncio.run(_run_all_bridges())
    except KeyboardInterrupt:
        logger.info("Shutting down All-in-One Multi-Tool MCP Server.")
