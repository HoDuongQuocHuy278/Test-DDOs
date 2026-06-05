#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Target Server - Flask Web Application (Nạn nhân để kiểm thử)
Chạy trên localhost:8080
"""

import os
import time
import logging
from datetime import datetime
from collections import deque
from threading import Lock
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Tắt log mặc định của Flask, dùng log riêng
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Stats tracking
request_stats = {
    'total': 0,
    'per_second': deque(maxlen=60),  # 60s window
    'last_second': 0,
    'current_second_count': 0,
    'start_time': datetime.now().isoformat(),
    'last_requests': deque(maxlen=100),
}
stats_lock = Lock()

HTML_PAGE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎯 Target Server — Security Lab</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 24px;
            max-width: 700px;
            width: 90%;
            box-shadow: 0 25px 50px rgba(0,0,0,0.5);
        }
        .target-badge {
            display: inline-block;
            background: rgba(255, 80, 80, 0.2);
            border: 1px solid rgba(255, 80, 80, 0.5);
            color: #ff5050;
            padding: 6px 18px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 10px rgba(255,80,80,0.3); }
            50% { opacity: 0.7; box-shadow: 0 0 25px rgba(255,80,80,0.6); }
        }
        h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 10px; }
        h1 span { color: #ff6b6b; }
        p.subtitle { color: rgba(255,255,255,0.6); margin-bottom: 30px; font-size: 1rem; }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 25px 0;
        }
        .stat-card {
            background: rgba(255,255,255,0.07);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 20px 15px;
        }
        .stat-value { font-size: 2rem; font-weight: 800; color: #00d4ff; }
        .stat-label { font-size: 0.75rem; color: rgba(255,255,255,0.5); margin-top: 5px; text-transform: uppercase; letter-spacing: 1px; }
        .online-dot {
            display: inline-block;
            width: 10px; height: 10px;
            background: #00ff88;
            border-radius: 50%;
            margin-right: 8px;
            animation: blink 1.5s infinite;
            box-shadow: 0 0 10px #00ff88;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; } 50% { opacity: 0.3; }
        }
        .endpoints {
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            padding: 20px;
            text-align: left;
            margin-top: 20px;
        }
        .endpoints h3 { color: #a78bfa; margin-bottom: 10px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
        .endpoint { 
            font-family: monospace; 
            font-size: 0.85rem; 
            color: #7dd3fc; 
            padding: 4px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .endpoint:last-child { border-bottom: none; }
        .method { color: #86efac; margin-right: 10px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="target-badge">🎯 TEST TARGET ACTIVE</div>
        <h1>Security <span>Lab</span> Server</h1>
        <p class="subtitle">
            <span class="online-dot"></span>
            Dang chay tren <strong id="srv-port">localhost</strong> — San sang de kiem thu
        </p>
        <div class="status-grid">
            <div class="stat-card">
                <div class="stat-value" id="total">—</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="rps">—</div>
                <div class="stat-label">Req/Second</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uptime">—</div>
                <div class="stat-label">Uptime (s)</div>
            </div>
        </div>
        <div class="endpoints">
            <h3>📡 Available Endpoints</h3>
            <div class="endpoint"><span class="method">GET</span>/</div>
            <div class="endpoint"><span class="method">GET</span>/api/health</div>
            <div class="endpoint"><span class="method">GET</span>/api/stats</div>
            <div class="endpoint"><span class="method">POST</span>/api/data</div>
            <div class="endpoint"><span class="method">GET</span>/heavy — CPU-intensive endpoint</div>
        </div>
    </div>
    <script>
        const start = Date.now();
        // Show actual port
        document.getElementById('srv-port').textContent = 'localhost:' + window.location.port;
        async function updateStats() {
            try {
                const r = await fetch('/api/stats');
                const d = await r.json();
                document.getElementById('total').textContent = d.total_requests.toLocaleString();
                document.getElementById('rps').textContent = d.requests_per_second;
                document.getElementById('uptime').textContent = Math.floor((Date.now() - start) / 1000);
            } catch(e) { document.getElementById('total').textContent = 'ERR'; }
        }
        setInterval(updateStats, 1000);
        updateStats();
    </script>
</body>
</html>"""


def track_request():
    with stats_lock:
        now = int(time.time())
        request_stats['total'] += 1
        if now != request_stats['last_second']:
            request_stats['per_second'].append(request_stats['current_second_count'])
            request_stats['current_second_count'] = 0
            request_stats['last_second'] = now
        request_stats['current_second_count'] += 1
        request_stats['last_requests'].append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'method': request.method,
            'path': request.path,
            'ip': request.remote_addr,
        })


@app.before_request
def before_request():
    track_request()


@app.route('/')
def index():
    return render_template_string(HTML_PAGE)


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'server': 'Security Lab Target Server',
        'time': datetime.now().isoformat(),
    })


@app.route('/api/stats')
def stats():
    with stats_lock:
        rps = request_stats['current_second_count']
        if request_stats['per_second']:
            recent = list(request_stats['per_second'])[-5:]
            rps = int(sum(recent) / max(len(recent), 1))
        return jsonify({
            'total_requests': request_stats['total'],
            'requests_per_second': rps,
            'recent_history': list(request_stats['per_second']),
            'last_requests': list(request_stats['last_requests'])[-20:],
            'start_time': request_stats['start_time'],
        })


@app.route('/api/data', methods=['POST'])
def data():
    time.sleep(0.01)  # Giả lập xử lý
    return jsonify({'received': True, 'size': request.content_length or 0})


@app.route('/heavy')
def heavy():
    """CPU-intensive endpoint để kiểm thử tải"""
    result = sum(i * i for i in range(100000))
    return jsonify({'result': result, 'status': 'computed'})


if __name__ == '__main__':
    import sys, io
    if sys.platform == 'win32':
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        except AttributeError:
            pass
    print("[*] Target Server dang khoi dong tren http://localhost:5000")
    print("    Su dung Ctrl+C de dung")
    app.run(host='0.0.0.0', port=int(os.environ.get('FLASK_PORT', 5000)), debug=False, threaded=True)


