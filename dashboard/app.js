/**
 * Security Testing Suite v3 — Dashboard JS
 * WAF + DDoS + Phishing + Ransomware
 */

const API_BASE = 'http://localhost:5100';
const WS_URL   = 'ws://localhost:8920/ws/live';
const DEFAULT_TARGET = () => 'http://localhost:5100';

// ── State ─────────────────────────────────────────────────────────────────────
let ws = null, wsRetry = 0;
let rpsChart = null;
let ddosRunning = false, enhancedRunning = false;
let selectedAttack = 'http_flood';
let selectedEnhanced = 'ua_flood';
let pollInterval = null;
let currentTab = 'ddos';

// ── Helpers ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString();

function addLog(level, msg) {
  const el = $('log-terminal');
  const t = new Date().toTimeString().slice(0,8);
  const div = document.createElement('div');
  div.className = 'log-entry';
  div.innerHTML = `<span class="log-time">${t}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span class="log-msg ${level}">${msg}</span>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  while (el.children.length > 200) el.removeChild(el.firstChild);
}

function clearLog() { $('log-terminal').innerHTML = ''; }

function setPill(id, online, text) {
  const el = $(id), dot = el.querySelector('.status-dot'), span = el.querySelector('span:last-child');
  dot.className = 'status-dot ' + (online ? 'online' : 'offline');
  span.textContent = text;
}

// ── Tab Switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-content').forEach(e => e.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(e => e.classList.remove('active'));
  $(`tab-content-${name}`).classList.add('active');
  $(`tab-${name}`).classList.add('active');
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    wsRetry = 0;
    setPill('api-status', true, 'API Online');
    addLog('success', 'Connected to API server');
    checkTarget();
  };

  ws.onmessage = e => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'log' && msg.entry) {
        addLog(msg.entry.level || 'info', msg.entry.message);
      } else if (msg.type === 'ddos_stats') {
        updateDDoSStats(msg.stats);
      } else if (msg.type === 'enhanced_ddos_stats') {
        updateDDoSStats(msg.stats);
      } else if (msg.type === 'init' && msg.logs) {
        msg.logs.slice(-20).forEach(l => addLog(l.level || 'info', l.message));
      }
    } catch(_) {}
  };

  ws.onclose = () => {
    setPill('api-status', false, 'API Offline');
    const delay = Math.min(30000, 2000 * (++wsRetry));
    setTimeout(connectWS, delay);
  };

  ws.onerror = () => ws.close();
}

// ── RPS Chart ─────────────────────────────────────────────────────────────────
function initChart() {
  const ctx = $('rps-chart').getContext('2d');
  rpsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'RPS',
        data: [],
        borderColor: '#f87171',
        backgroundColor: 'rgba(248,113,113,0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: false,
      scales: {
        x: { display: false },
        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function pushChart(rps) {
  const d = rpsChart.data;
  const t = new Date().toTimeString().slice(0,8);
  d.labels.push(t);
  d.datasets[0].data.push(rps);
  if (d.labels.length > 60) { d.labels.shift(); d.datasets[0].data.shift(); }
  rpsChart.update('none');
}

function clearChart() {
  rpsChart.data.labels = [];
  rpsChart.data.datasets[0].data = [];
  rpsChart.update();
}

// ── DDoS Stats Update ─────────────────────────────────────────────────────────
function updateDDoSStats(stats) {
  if (!stats) return;
  const sent = stats.sent || 0, rps = stats.rps || 0;
  $('s-total-sent').textContent = fmt(sent);
  $('s-total-ok').textContent = fmt(stats.success || 0) + ' OK';
  $('s-rps').textContent = fmt(rps);
  $('d-sent').textContent = fmt(sent);
  $('d-rps').textContent = fmt(rps);
  $('d-elapsed').textContent = (stats.elapsed || 0) + 's';
  if (stats.running !== false) pushChart(rps);
}

// ── Attack Selector ──────────────────────────────────────────────────────────
function selectAttack(type) {
  selectedAttack = type;
  document.querySelectorAll('.attack-type-card').forEach(e => e.classList.remove('active'));
  $('atk-' + type)?.classList.add('active');
}

function selectEnhanced(type) {
  selectedEnhanced = type;
  document.querySelectorAll('.enhanced-card').forEach(e => e.classList.remove('active'));
  $('enh-' + type)?.classList.add('active');
}

// ── Standard DDoS ─────────────────────────────────────────────────────────────
async function startDDoS() {
  const target = $('ddos-target').value || DEFAULT_TARGET();
  const workers = +$('ddos-workers').value;
  const duration = +$('ddos-duration').value;

  $('btn-ddos-start').disabled = true;
  $('btn-ddos-stop').disabled = false;
  $('ddos-badge').textContent = 'RUNNING';
  $('ddos-badge').className = 'badge badge-red';
  $('s-attack-type').textContent = selectedAttack;
  $('attack-progress-wrap').style.display = 'block';
  $('attack-progress-bar').style.transition = `width ${duration}s linear`;
  setTimeout(() => $('attack-progress-bar').style.width = '100%', 50);

  addLog('warning', `Launching ${selectedAttack} → ${target} (${workers}w, ${duration}s)`);

  try {
    const r = await fetch(`${API_BASE}/api/ddos/start`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ target_url: target, attack_type: selectedAttack, workers, duration })
    });
    if (!r.ok) { const d = await r.json(); addLog('error', d.detail || 'Start failed'); return; }
    ddosRunning = true;
    pollInterval = setInterval(pollDDoSStats, 800);
    setTimeout(stopDDoS, duration * 1000 + 2000);
  } catch(e) { addLog('error', 'DDoS start failed: ' + e.message); resetDDoSUI(); }
}

async function stopDDoS() {
  clearInterval(pollInterval);
  try { await fetch(`${API_BASE}/api/ddos/stop`, {method:'POST'}); } catch(_) {}
  resetDDoSUI();
  addLog('info', 'DDoS attack stopped');
}

async function pollDDoSStats() {
  try {
    const r = await fetch(`${API_BASE}/api/ddos/stats`);
    const d = await r.json();
    updateDDoSStats(d.stats || d);
    if (!d.running && !d.is_running) { clearInterval(pollInterval); resetDDoSUI(); }
  } catch(_) {}
}

function resetDDoSUI() {
  ddosRunning = false;
  $('btn-ddos-start').disabled = false;
  $('btn-ddos-stop').disabled = true;
  $('ddos-badge').textContent = 'IDLE';
  $('attack-progress-bar').style.width = '0%';
  $('attack-progress-wrap').style.display = 'none';
  $('s-attack-type').textContent = 'Idle';
}

// ── Enhanced DDoS ─────────────────────────────────────────────────────────────
async function startEnhanced() {
  const target = $('enhanced-target').value || DEFAULT_TARGET();
  const workers = +$('enhanced-workers').value;
  const duration = +$('enhanced-duration').value;

  $('btn-enhanced-start').disabled = true;
  $('btn-enhanced-stop').disabled = false;
  $('enhanced-badge').textContent = 'RUNNING';
  addLog('warning', `Enhanced DDoS: ${selectedEnhanced} → ${target}`);

  try {
    const r = await fetch(`${API_BASE}/api/ddos/enhanced/start`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ target_url: target, attack_type: selectedEnhanced, workers, duration })
    });
    if (!r.ok) { const d = await r.json(); addLog('error', d.detail || 'Failed'); resetEnhancedUI(); return; }
    const poll = setInterval(async () => {
      try {
        const s = await fetch(`${API_BASE}/api/ddos/enhanced/stats`);
        const sd = await s.json();
        updateDDoSStats(sd);
        if (!sd.running) { clearInterval(poll); resetEnhancedUI(); }
      } catch(_) {}
    }, 800);
    setTimeout(() => { clearInterval(poll); stopEnhanced(); }, duration * 1000 + 3000);
  } catch(e) { addLog('error', 'Enhanced start failed: ' + e.message); resetEnhancedUI(); }
}

async function stopEnhanced() {
  try { await fetch(`${API_BASE}/api/ddos/enhanced/stop`, {method:'POST'}); } catch(_) {}
  resetEnhancedUI();
}

function resetEnhancedUI() {
  $('btn-enhanced-start').disabled = false;
  $('btn-enhanced-stop').disabled = true;
  $('enhanced-badge').textContent = 'IDLE';
}

// ── WAF Scanner ───────────────────────────────────────────────────────────────
async function startWAFScan() {
  const url = $('waf-url').value || DEFAULT_TARGET();
  const timeout = +$('waf-timeout').value;
  const findAll = $('waf-findall').checked;

  $('btn-waf-scan').disabled = true;
  $('btn-waf-scan').innerHTML = '<span class="spinner"></span>Scanning...';
  $('waf-badge').textContent = 'SCANNING';
  $('waf-result-content').innerHTML = '';
  $('waf-raw-output').style.display = 'none';
  addLog('info', `WAF scan: ${url}`);

  try {
    const r = await fetch(`${API_BASE}/api/waf/scan-simple?url=${encodeURIComponent(url)}&timeout=${timeout}`);
    const d = await r.json();
    renderWAFResult(d);
  } catch(e) {
    $('waf-result-content').innerHTML = `<div class="waf-result-card waf-detected"><p style="color:var(--accent-red)">Error: ${e.message}</p></div>`;
  } finally {
    $('btn-waf-scan').disabled = false;
    $('btn-waf-scan').innerHTML = '🔍 Start WAF Scan';
    $('waf-badge').textContent = 'DONE';
  }
}

function renderWAFResult(d) {
  const box = $('waf-result-content');
  if (d.waf_detected) {
    box.innerHTML = `<div class="waf-result-card waf-detected">
      <div style="font-size:2rem">🛡️</div>
      <div style="font-size:1.2rem;font-weight:800;color:var(--accent-red);margin:8px 0">WAF Detected!</div>
      <div style="font-size:1rem;color:var(--accent-orange)">${d.waf_name || 'Unknown WAF'}</div>
      ${d.manufacturer ? `<div style="font-size:.8rem;color:var(--text-muted)">${d.manufacturer}</div>` : ''}
    </div>`;
    addLog('warning', `WAF Detected: ${d.waf_name}`);
  } else {
    box.innerHTML = `<div class="waf-result-card waf-clean">
      <div style="font-size:2rem">✅</div>
      <div style="font-size:1.1rem;font-weight:800;color:var(--accent-green);margin:8px 0">No WAF Detected</div>
      <div style="font-size:.82rem;color:var(--text-muted)">Site appears to be running without a WAF</div>
    </div>`;
    addLog('info', 'No WAF detected');
  }
  if (d.raw_output) {
    const raw = $('waf-raw-output');
    raw.textContent = d.raw_output.slice(0, 2000);
    raw.style.display = 'block';
  }
}

function clearWAFResult() {
  $('waf-result-content').innerHTML = '';
  $('waf-raw-output').style.display = 'none';
  $('waf-badge').textContent = 'READY';
}

// ── Phishing Test ─────────────────────────────────────────────────────────────
async function runPhishingTest() {
  const url = $('phishing-url').value || DEFAULT_TARGET();
  const timeout = +$('phishing-timeout').value;
  const btn = $('btn-phishing-run');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Testing...';
  $('phishing-badge').textContent = 'RUNNING';
  $('phishing-score-box').style.display = 'none';
  $('phishing-results').innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px">Running security checks... please wait</div>';
  addLog('info', `Phishing test: ${url}`);

  try {
    const r = await fetch(`${API_BASE}/api/security/phishing-test`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url, timeout })
    });
    const d = await r.json();
    renderPhishingResult(d);
  } catch(e) {
    $('phishing-results').innerHTML = `<div style="color:var(--accent-red);padding:16px">Error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🎣 Run Phishing Test';
    $('phishing-badge').textContent = 'DONE';
  }
}

function renderPhishingResult(d) {
  const score = d.total_score || 0;
  const grade = d.grade || 'F';

  // Score color
  const col = score >= 80 ? 'var(--accent-green)' : score >= 60 ? 'var(--accent-yellow)' : score >= 40 ? 'var(--accent-orange)' : 'var(--accent-red)';
  const desc = score >= 80 ? 'Excellent Security!' : score >= 60 ? 'Good — some improvements needed' : score >= 40 ? 'Moderate risk — fix issues before launch' : 'HIGH RISK — critical issues found!';

  // Update global stat
  $('s-security-score').textContent = score;
  $('s-security-grade').textContent = 'Phishing: ' + grade;

  $('phishing-score-num').textContent = score;
  $('phishing-score-num').style.color = col;
  $('phishing-score-circle').style.borderColor = col;
  $('phishing-grade').textContent = grade;
  $('phishing-grade').style.color = col;
  $('phishing-desc').textContent = desc;
  $('phishing-meta').textContent = `HTTPS: ${d.is_https ? '✅' : '❌'} | Server: ${d.server_info || '?'} | Time: ${d.elapsed}s`;

  // Summary pills
  const sum = d.summary || {};
  $('phishing-summary').innerHTML = Object.entries(sum).map(([k,v]) =>
    `<span class="check-pill ${k}">${v} ${k.toUpperCase()}</span>`
  ).join('');

  $('phishing-score-box').style.display = 'block';

  // Checks list — group by category
  const cats = {};
  (d.checks || []).forEach(c => { (cats[c.category] = cats[c.category] || []).push(c); });

  let html = '';
  Object.entries(cats).forEach(([cat, items]) => {
    html += `<div style="font-size:.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.1em;margin:16px 0 8px">${cat}</div>`;
    items.forEach(c => {
      const sev = c.severity === 'critical' ? '🔴' : c.severity === 'high' ? '🟠' : c.severity === 'medium' ? '🟡' : '🟢';
      html += `<div class="check-item ${c.status}">
        <div class="check-item-header">
          <span class="check-item-name">${sev} ${c.name}</span>
          <span class="check-item-cat">${c.status.toUpperCase()}</span>
        </div>
        <div class="check-item-detail">${c.detail}</div>
        ${c.recommendation ? `<div class="check-item-rec">💡 ${c.recommendation}</div>` : ''}
      </div>`;
    });
  });
  $('phishing-results').innerHTML = html;
  addLog(score >= 60 ? 'success' : 'warning', `Phishing test done — Score: ${score}/100 (${grade})`);
}

// ── Ransomware Test ────────────────────────────────────────────────────────────
async function runRansomwareTest() {
  const url = $('ransomware-url').value || DEFAULT_TARGET();
  const timeout = +$('ransomware-timeout').value;
  const btn = $('btn-ransomware-run');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Scanning vulnerabilities...';
  $('ransomware-badge').textContent = 'SCANNING';
  $('ransomware-risk-box').style.display = 'none';
  $('ransomware-results').innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px">Running vulnerability scan... this may take 30-60 seconds</div>';
  addLog('warning', `Ransomware resilience test: ${url}`);

  try {
    const r = await fetch(`${API_BASE}/api/security/ransomware-test`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url, timeout })
    });
    const d = await r.json();
    renderRansomwareResult(d);
  } catch(e) {
    $('ransomware-results').innerHTML = `<div style="color:var(--accent-red);padding:16px">Error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔐 Run Vulnerability Scan';
    $('ransomware-badge').textContent = 'DONE';
  }
}

function renderRansomwareResult(d) {
  const risk = d.overall_risk || 'Unknown';
  const score = d.risk_score || 0;
  const riskColors = { Critical:'#ef4444', High:'var(--accent-orange)', Medium:'var(--accent-yellow)', Low:'var(--accent-green)', Safe:'var(--accent-blue)' };
  const col = riskColors[risk] || 'var(--text-secondary)';

  $('ransomware-risk-fill').style.width = score + '%';
  $('ransomware-risk-level').textContent = risk;
  $('ransomware-risk-level').style.color = col;
  $('ransomware-counts').innerHTML = `
    <span class="risk-badge critical">${d.critical_count || 0} Critical</span>
    <span class="risk-badge high">${d.high_count || 0} High</span>
    <span class="risk-badge medium">${d.medium_count || 0} Medium</span>
  `;
  $('ransomware-risk-box').style.display = 'block';

  let html = '';
  (d.results || []).forEach(r => {
    const icon = r.status === 'vulnerable' ? '🔴' : r.status === 'warn' ? '🟡' : r.status === 'safe' ? '🟢' : 'ℹ️';
    html += `<div class="check-item ${r.status}">
      <div class="check-item-header">
        <span class="check-item-name">${icon} ${r.test_name}</span>
        <span class="check-item-cat">${r.category}</span>
      </div>
      <div class="check-item-detail">${r.detail}</div>
      ${r.recommendation ? `<div class="check-item-rec">💡 ${r.recommendation}</div>` : ''}
      ${r.payload_used && r.status === 'vulnerable' ? `<div style="margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--accent-red);background:rgba(239,68,68,.08);padding:4px 8px;border-radius:6px">Payload: ${r.payload_used}</div>` : ''}
    </div>`;
  });
  $('ransomware-results').innerHTML = html;

  const logLevel = risk === 'Critical' || risk === 'High' ? 'error' : risk === 'Medium' ? 'warning' : 'success';
  addLog(logLevel, `Ransomware scan done — Risk: ${risk} (${score}/100)`);
}

// ── Target Monitor ────────────────────────────────────────────────────────────
async function checkTarget() {
  const url = $('ddos-target')?.value || DEFAULT_TARGET();
  try {
    const [sr, st] = await Promise.all([
      fetch(`${API_BASE}/api/target/status?url=${encodeURIComponent(url)}`).catch(() => null),
      fetch(`${API_BASE}/api/target/stats?url=${encodeURIComponent(url)}`).catch(() => null),
    ]);

    if (sr?.ok) {
      const sd = await sr.json();
      const alive = sd.alive;
      const latency = sd.latency_ms || 0;

      setPill('target-status', alive, alive ? `Target Online (${latency}ms)` : 'Target Offline');
      $('target-dot').style.background = alive ? 'var(--accent-green)' : 'var(--accent-red)';
      $('target-status-detail').textContent = alive ? `Online — ${latency}ms` : 'Offline';
      $('s-latency').textContent = alive ? latency + 'ms' : '—';
      $('s-target-alive').textContent = alive ? 'Target Online' : 'Target Down';
      const pct = Math.min(100, (latency / 2000) * 100);
      $('latency-bar').style.width = pct + '%';
      $('latency-text').textContent = latency + ' ms';
    }

    if (st?.ok) {
      const td = await st.json();
      $('srv-total').textContent = fmt(td.total_requests);
      $('srv-rps').textContent = td.requests_per_second || '—';
    }
  } catch(_) {}
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => {
  initChart();
  connectWS();
  setInterval(checkTarget, 5000);
  checkTarget();
  selectAttack('http_flood');
  selectEnhanced('ua_flood');
});
