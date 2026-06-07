#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Server - FastAPI Backend
Điều khiển WAF scanner và DDoS engine từ Dashboard Web UI.
Chạy trên localhost:9000
"""

import sys
import os
import json
import asyncio
import subprocess
import threading
import time
import logging
import requests as req_lib
from typing import Optional, List, Dict, Any
from datetime import datetime
from collections import deque

# Thêm thư mục gốc vào path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ddos_engine.stress_test import get_orchestrator
from security_engine.phishing_test import run_phishing_test
from security_engine.ransomware_test import run_ransomware_test
from security_engine.enhanced_ddos import get_enhanced_engine, EnhancedDDoSEngine

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('api_server')

# ─── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Testing Suite API",
    description="WAF Detection + DDoS + Phishing Resistance + Ransomware Resilience Testing",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (dashboard)
dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard')
if os.path.exists(dashboard_path):
    app.mount("/dashboard", StaticFiles(directory=dashboard_path, html=True), name="dashboard")

# ─── WebSocket Manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
        self._lock = threading.Lock()  # Use threading.Lock — safe outside async context

    async def connect(self, ws: WebSocket):
        await ws.accept()
        with self._lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict):
        data = json.dumps(message, ensure_ascii=False)
        with self._lock:
            clients = list(self.active)
        dead = []
        for ws in clients:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            with self._lock:
                if ws in self.active:
                    self.active.remove(ws)

manager = ConnectionManager()


# ─── Event Log ────────────────────────────────────────────────────────────────
event_log: deque = deque(maxlen=500)
_main_loop: asyncio.AbstractEventLoop = None

def add_log(level: str, message: str, data: dict = None):
    entry = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'level': level,
        'message': message,
        'data': data or {},
    }
    event_log.append(entry)
    # Broadcast async trong background - guard against None loop
    if _main_loop is not None and not _main_loop.is_closed():
        try:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast({'type': 'log', 'entry': entry}),
                _main_loop
            )
        except Exception:
            pass

# ─── Pydantic Models ──────────────────────────────────────────────────────────
class WAFScanRequest(BaseModel):
    url: str
    find_all: bool = False
    timeout: int = 10

class DDoSStartRequest(BaseModel):
    target_url: str
    attack_type: str = 'http_flood'
    workers: int = 500       # default 500, UI max = 2000
    duration: int = 60       # default 60s, UI max = 600s
    rate_limit: Optional[int] = None
    num_sockets: int = 1000  # Slowloris: max sockets

class EnhancedDDoSRequest(BaseModel):
    target_url: str
    attack_type: str = 'ua_flood'   # xml_bomb|large_payload|header_overflow|cache_bypass|ua_flood
    workers: int = 500       # default 500, UI max = 2000
    duration: int = 60       # default 60s, UI max = 600s

class PhishingTestRequest(BaseModel):
    url: str
    timeout: int = 10

class RansomwareTestRequest(BaseModel):
    url: str
    timeout: int = 8
    aggressive: bool = False

class TargetCheckRequest(BaseModel):
    url: str

# ─── WAF Scanning ─────────────────────────────────────────────────────────────
@app.post("/api/waf/scan")
async def waf_scan(body: WAFScanRequest):
    """Chạy wafw00f để phát hiện WAF."""
    url = body.url
    if not url.startswith('http'):
        url = 'http://' + url

    add_log('info', f'Bắt đầu WAF scan: {url}')

    wafw00f_dir = os.path.join(os.path.dirname(__file__), 'wafw00f')

    try:
        cmd = [
            sys.executable, '-m', 'wafw00f.main',
            url,
            '-o', '-',
            '-f', 'json',
            '-T', str(body.timeout),
        ]
        if body.find_all:
            cmd.append('-a')

        result = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=wafw00f_dir,
        )
        stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=60)

        output_text = stdout.decode('utf-8', errors='replace')
        stderr_text = stderr.decode('utf-8', errors='replace')

        # Tìm JSON output
        waf_results = []
        try:
            # wafw00f output JSON khi dùng -o - -f json
            json_data = json.loads(output_text.strip())
            if isinstance(json_data, list):
                waf_results = json_data
            else:
                waf_results = [json_data]
        except json.JSONDecodeError:
            # Parse text output
            pass

        add_log('success', f'WAF scan hoàn thành: {url}', {'results': waf_results})

        return {
            'success': True,
            'url': url,
            'results': waf_results,
            'raw_output': output_text + stderr_text,
            'timestamp': datetime.now().isoformat(),
        }

    except asyncio.TimeoutError:
        add_log('error', f'WAF scan timeout: {url}')
        raise HTTPException(status_code=408, detail='Scan timeout')
    except Exception as e:
        add_log('error', f'WAF scan lỗi: {str(e)}')
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/waf/scan-simple")
async def waf_scan_simple(url: str, timeout: int = 10):
    """Quét WAF đơn giản, parse kết quả từ text output."""
    if not url.startswith('http'):
        url = 'http://' + url

    add_log('info', f'WAF scan (simple mode): {url}')

    wafw00f_dir = os.path.join(os.path.dirname(__file__), 'wafw00f')

    try:
        cmd = [sys.executable, '-m', 'wafw00f.main', url, '-T', str(timeout)]

        result = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=wafw00f_dir,
        )
        stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=60)

        output = stdout.decode('utf-8', errors='replace') + stderr.decode('utf-8', errors='replace')

        # Parse kết quả từ text
        detected = False
        waf_name = None
        manufacturer = None
        no_waf = False

        for line in output.splitlines():
            line = line.strip()
            if 'is behind' in line:
                detected = True
                # Trích xuất WAF name
                try:
                    parts = line.split('is behind')
                    waf_info = parts[1].strip().rstrip('WAF.').strip()
                    # Remove ANSI codes
                    import re
                    waf_info = re.sub(r'\x1b\[[0-9;]*m', '', waf_info).strip()
                    if '(' in waf_info:
                        waf_name = waf_info.split('(')[0].strip()
                        manufacturer = waf_info.split('(')[1].replace(')', '').strip()
                    else:
                        waf_name = waf_info
                except Exception:
                    pass
            elif 'No WAF detected' in line or 'not behind' in line.lower():
                no_waf = True

        add_log('success', f'WAF scan xong: {"Detected " + str(waf_name) if detected else "No WAF"}')

        return {
            'success': True,
            'url': url,
            'waf_detected': detected,
            'waf_name': waf_name,
            'manufacturer': manufacturer,
            'no_waf': no_waf,
            'raw_output': output,
            'timestamp': datetime.now().isoformat(),
        }

    except asyncio.TimeoutError:
        add_log('error', f'WAF scan timeout')
        raise HTTPException(status_code=408, detail='Timeout')
    except Exception as e:
        add_log('error', f'Lỗi: {str(e)}')
        raise HTTPException(status_code=500, detail=str(e))


# ─── DDoS Control ────────────────────────────────────────────────────────────
@app.post("/api/ddos/start")
async def ddos_start(body: DDoSStartRequest):
    """Bắt đầu tấn công DDoS."""
    orch = get_orchestrator()

    if orch.is_running:
        raise HTTPException(status_code=409, detail='Một attack đang chạy. Dừng trước.')

    def stats_cb(stats):
        if _main_loop is not None and not _main_loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({'type': 'ddos_stats', 'stats': stats}),
                    _main_loop
                )
            except Exception:
                pass

    target_url = body.target_url
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url

    add_log('warning', f'Bắt đầu {body.attack_type} → {target_url}', {
        'workers': body.workers,
        'duration': body.duration,
    })

    if body.attack_type in ('http_flood', 'get_flood'):
        started = orch.start_http_flood(
            target_url=target_url,
            method='GET',
            workers=body.workers,
            duration=body.duration,
            rate_limit=body.rate_limit,
            stats_callback=stats_cb,
        )
    elif body.attack_type == 'post_flood':
        started = orch.start_http_flood(
            target_url=target_url,
            method='POST',
            workers=body.workers,
            duration=body.duration,
            rate_limit=body.rate_limit,
            stats_callback=stats_cb,
        )
    elif body.attack_type == 'slowloris':
        import urllib.parse
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or 80

        started = orch.start_slowloris(
            host=host,
            port=port,
            num_sockets=body.num_sockets,
            duration=body.duration,
            stats_callback=stats_cb,
        )
    else:
        raise HTTPException(status_code=400, detail=f'Unknown attack type: {body.attack_type}')

    if not started:
        raise HTTPException(status_code=409, detail='Không thể bắt đầu attack')

    return {
        'success': True,
        'attack_type': body.attack_type,
        'target': target_url,
        'duration': body.duration,
        'message': 'Attack đã bắt đầu',
    }


@app.post("/api/ddos/stop")
async def ddos_stop():
    """Dừng attack đang chạy."""
    orch = get_orchestrator()
    result = orch.stop()
    add_log('info', 'Attack đã dừng', result)
    return result


@app.get("/api/ddos/stats")
async def ddos_stats():
    """Lấy stats hiện tại của attack."""
    orch = get_orchestrator()
    return orch.get_stats()


# ─── Target Status ────────────────────────────────────────────────────────────
@app.get("/api/target/status")
async def target_status(url: str = 'http://localhost:8080'):
    """Kiểm tra target server còn sống không."""
    try:
        start = time.time()
        r = req_lib.get(url + '/api/health', timeout=3)
        latency = round((time.time() - start) * 1000, 1)
        return {
            'alive': True,
            'status_code': r.status_code,
            'latency_ms': latency,
            'url': url,
        }
    except req_lib.exceptions.ConnectionError:
        return {'alive': False, 'url': url, 'error': 'Connection refused'}
    except req_lib.exceptions.Timeout:
        return {'alive': False, 'url': url, 'error': 'Timeout (server overloaded?)'}
    except Exception as e:
        return {'alive': False, 'url': url, 'error': str(e)}


@app.get("/api/target/stats")
async def target_stats(url: str = 'http://localhost:8080'):
    """Lấy stats từ target server."""
    try:
        r = req_lib.get(url + '/api/stats', timeout=3)
        return r.json()
    except Exception as e:
        return {'error': str(e)}


# ─── Logs ─────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def get_logs(limit: int = 100):
    """Lấy event logs."""
    return list(event_log)[-limit:]


# ═══════════════════════════════════════════════════════════════════════════════
# ─── Phishing Resistance Test ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/security/phishing-test")
async def phishing_test(body: PhishingTestRequest):
    """Kiem tra kha nang chong Phishing cua website."""
    url = body.url if body.url.startswith('http') else 'http://' + body.url
    add_log('info', f'Bat dau Phishing Resistance Test: {url}')

    def progress_cb(level, msg):
        add_log(level, f'[Phishing] {msg}')

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: run_phishing_test(url, timeout=body.timeout, callback=progress_cb)
        )
        add_log('success' if result['total_score'] >= 60 else 'warning',
                f'Phishing Test hoan thanh — Score: {result["total_score"]}/100 Grade: {result["grade"]}')
        return result
    except Exception as e:
        add_log('error', f'Phishing test loi: {str(e)}')
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# ─── Ransomware Resilience Test ───────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/security/ransomware-test")
async def ransomware_test(body: RansomwareTestRequest):
    """Kiem tra kha nang chiu dung truoc tan cong Ransomware/Vulnerability."""
    url = body.url if body.url.startswith('http') else 'http://' + body.url
    add_log('warning', f'Bat dau Ransomware Resilience Test: {url}')

    def progress_cb(level, msg):
        add_log(level, f'[Ransomware] {msg}')

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: run_ransomware_test(url, timeout=body.timeout, callback=progress_cb)
        )
        risk = result.get('overall_risk', 'Unknown')
        level = 'error' if risk in ('Critical', 'High') else ('warning' if risk == 'Medium' else 'success')
        add_log(level, f'Ransomware Test hoan thanh — Risk: {risk} ({result["risk_score"]}/100)')
        return result
    except Exception as e:
        add_log('error', f'Ransomware test loi: {str(e)}')
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# ─── Enhanced DDoS ────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ddos/enhanced/types")
async def enhanced_ddos_types():
    """Danh sach cac kieu tan cong nang cao."""
    return EnhancedDDoSEngine.ATTACK_TYPES


@app.post("/api/ddos/enhanced/start")
async def enhanced_ddos_start(body: EnhancedDDoSRequest):
    """Bat dau enhanced DDoS attack."""
    eng = get_enhanced_engine()
    if eng.is_running:
        raise HTTPException(status_code=409, detail='Enhanced attack dang chay. Stop truoc.')

    url = body.target_url if body.target_url.startswith('http') else 'http://' + body.target_url
    atk_info = EnhancedDDoSEngine.ATTACK_TYPES.get(body.attack_type, {})
    add_log('warning', f'Enhanced DDoS: {atk_info.get("name", body.attack_type)} -> {url}')

    def stats_cb(stats):
        if _main_loop is not None and not _main_loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({'type': 'enhanced_ddos_stats', 'stats': stats}),
                    _main_loop
                )
            except Exception:
                pass

    started = eng.start(
        url=url,
        attack_type=body.attack_type,
        workers=body.workers,
        duration=body.duration,
        stats_callback=stats_cb,
    )

    if not started:
        raise HTTPException(status_code=409, detail='Khong the bat dau attack')

    return {
        'success': True,
        'attack_type': body.attack_type,
        'attack_name': atk_info.get('name', body.attack_type),
        'target': url,
        'workers': body.workers,
        'duration': body.duration,
    }


@app.post("/api/ddos/enhanced/stop")
async def enhanced_ddos_stop():
    """Dung enhanced attack."""
    eng = get_enhanced_engine()
    result = eng.stop()
    add_log('info', f'Enhanced attack stopped. Stats: {result}')
    return result


@app.get("/api/ddos/enhanced/stats")
async def enhanced_ddos_stats():
    """Stats cua enhanced attack."""
    eng = get_enhanced_engine()
    return eng.get_stats()


# ─── WebSocket ────────────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    add_log('info', 'Dashboard client kết nối')
    try:
        # Gửi logs cũ
        await websocket.send_text(json.dumps({
            'type': 'init',
            'logs': list(event_log)[-50:],
        }))

        # Ping-pong để giữ kết nối
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == 'ping':
                    await websocket.send_text(json.dumps({'type': 'pong'}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({'type': 'ping'}))

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        add_log('info', 'Dashboard client ngắt kết nối')


# ─── Root ──────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    dashboard_index = os.path.join(dashboard_path, 'index.html')
    if os.path.exists(dashboard_index):
        return FileResponse(dashboard_index)
    return {
        'name': 'Security Testing Suite API',
        'version': '2.0.0',
        'dashboard': 'http://localhost:9000/dashboard',
        'docs': 'http://localhost:9000/docs',
    }


@app.on_event("startup")
async def startup_event():
    global _main_loop
    _main_loop = asyncio.get_event_loop()
    add_log('success', '🚀 Security Testing Suite API khởi động tại http://localhost:9000')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=9000, log_level='warning')
