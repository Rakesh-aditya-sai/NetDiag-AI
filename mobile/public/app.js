const NetDiag = (window.Capacitor && window.Capacitor.Plugins) ? window.Capacitor.Plugins.NetDiag : null;

const targetInput = document.getElementById('target');
const customPortsInput = document.getElementById('customPorts');
const runBtn = document.getElementById('runBtn');
const errorMsg = document.getElementById('errorMsg');
const spinner = document.getElementById('spinner');
const resultsSection = document.getElementById('resultsSection');
const resultsList = document.getElementById('resultsList');
const resultTarget = document.getElementById('resultTarget');
const suggestionsList = document.getElementById('suggestionsList');
const exportBtn = document.getElementById('exportBtn');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');
const checkboxes = document.querySelectorAll('.checks input[type="checkbox"]');

let lastReport = null;

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$/;
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;

function isValidTarget(target) {
  if (!target || target.length > 253) return false;
  return IPV4_RE.test(target) || IPV6_RE.test(target) || HOSTNAME_RE.test(target);
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.hidden = !msg;
}

function selectedChecks() {
  return Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value);
}

const CHECK_LABELS = {
  connectivity: 'Connectivity (Ping)',
  dns: 'DNS Resolution',
  firewall: 'Firewall / Port Check',
  traceroute: 'Traceroute',
  cloud: 'Cloud / HTTP(S) Reachability',
  ssl: 'SSL/TLS Certificate Info',
};

async function runCheck(id, target, customPorts) {
  try {
    let result;
    switch (id) {
      case 'connectivity': result = await NetDiag.ping({ target }); break;
      case 'dns': result = await NetDiag.dns({ target }); break;
      case 'firewall': result = await NetDiag.firewall({ target, customPorts }); break;
      case 'traceroute': result = await NetDiag.traceroute({ target }); break;
      case 'cloud': result = await NetDiag.cloud({ target }); break;
      case 'ssl': result = await NetDiag.sslInfo({ target, port: 443 }); break;
      default: throw new Error('Unknown check: ' + id);
    }
    return { id, name: CHECK_LABELS[id], status: result.status, detail: result.detail, raw: result };
  } catch (e) {
    return { id, name: CHECK_LABELS[id], status: 'FAIL', detail: 'Check failed to run: ' + (e.message || e), raw: {} };
  }
}

const STATUS_RANK = { PASS: 0, WARNING: 1, FAIL: 2 };

function overallStatus(results) {
  let worst = 'PASS';
  for (const r of results) {
    if ((STATUS_RANK[r.status] ?? 2) > STATUS_RANK[worst]) worst = r.status;
  }
  return worst;
}

function buildMetrics(results) {
  const byId = {};
  for (const r of results) byId[r.id] = r.raw || {};
  const ping = byId.connectivity || {};
  const dns = byId.dns || {};
  const traceroute = byId.traceroute || {};
  const firewall = byId.firewall || {};
  return {
    avgLatencyMs: ping.avgLatencyMs ?? null,
    minLatencyMs: ping.minLatencyMs ?? null,
    maxLatencyMs: ping.maxLatencyMs ?? null,
    jitterMs: ping.jitterMs ?? null,
    packetLossPct: ping.packetLossPct ?? null,
    dnsResponseMs: dns.dnsResponseMs ?? null,
    resolvedIp: dns.resolvedIp ?? null,
    hopCount: traceroute.hopCount ?? null,
    openPorts: firewall.openPorts ?? null,
    closedPorts: firewall.closedPorts ?? null,
    sslDaysUntilExpiry: (byId.ssl || {}).daysUntilExpiry ?? null,
  };
}

function analyze(results) {
  const byName = {};
  for (const r of results) byName[r.name] = r.status;

  const suggestions = [];
  const ping = byName['Connectivity (Ping)'];
  const dnsStatus = byName['DNS Resolution'];
  const fw = byName['Firewall / Port Check'];
  const cloud = byName['Cloud / HTTP(S) Reachability'];

  if (dnsStatus === 'FAIL') {
    suggestions.push('DNS resolution failed. Verify the hostname is correct and that your device has a working DNS server (check WiFi/mobile data DNS settings).');
  }
  if (ping === 'FAIL' && dnsStatus === 'FAIL') {
    suggestions.push('Both DNS and ICMP failed — check basic network path: WiFi/mobile connectivity, VPN status, and upstream link.');
  } else if (ping === 'FAIL' && (dnsStatus === 'PASS' || dnsStatus === 'WARNING' || dnsStatus === undefined)) {
    suggestions.push('The address resolves fine but does not respond to ICMP. This usually means a firewall (host-based or network) is blocking ICMP, or the host is powered off / disconnected.');
  }
  if (ping === 'PASS' && fw === 'WARNING') {
    suggestions.push('Host answers pings but no common service ports are open. If a specific service should be running, check that it is bound and listening, and that firewall rules allow the port.');
  }
  if (cloud === 'FAIL' && ping === 'PASS') {
    suggestions.push('Host is reachable at the network layer but HTTP/HTTPS is not responding — check the web service status and any reverse proxy/load balancer in front of it.');
  }
  if (results.length > 0 && results.every(r => r.status === 'PASS')) {
    suggestions.push('All checks passed. No further action needed.');
  }
  if (suggestions.length === 0) {
    suggestions.push('Review the individual check details above for anomalies; no clear single root cause pattern was detected.');
  }
  return suggestions;
}

async function getDeviceContext() {
  if (!NetDiag || !NetDiag.getDeviceContext) return null;
  try {
    return await NetDiag.getDeviceContext();
  } catch (e) {
    return null;
  }
}

function renderEnvironment(env, durationMs) {
  const box = document.getElementById('environmentBox');
  if (!box) return;
  if (!env) {
    box.innerHTML = '';
    box.hidden = true;
    return;
  }
  const parts = [];
  if (env.connectionType) parts.push(`Connection: ${env.connectionType}${env.vpnActive ? ' (+ VPN)' : ''}`);
  if (env.localIp) parts.push(`Local IP: ${env.localIp}`);
  if (env.gatewayIp) parts.push(`Gateway: ${env.gatewayIp}`);
  if (env.privateDnsMode) parts.push(`Private DNS: ${env.privateDnsMode}`);
  if (env.deviceModel) parts.push(`Device: ${env.deviceModel}`);
  if (env.androidVersion) parts.push(`Android: ${env.androidVersion}`);
  if (env.appVersion) parts.push(`App: v${env.appVersion}`);
  if (durationMs != null) parts.push(`Run duration: ${(durationMs / 1000).toFixed(1)}s`);
  box.innerHTML = '<h3>Environment</h3><div class="meta env-grid"></div>';
  const grid = box.querySelector('.env-grid');
  grid.textContent = parts.join('  ·  ');
  box.hidden = parts.length === 0;
}

function renderResults(data) {
  resultTarget.textContent = data.target;
  resultsList.innerHTML = '';
  renderEnvironment(data.environment, data.durationMs);

  for (const r of data.results) {
    const item = document.createElement('div');
    item.className = 'result-item';
    item.innerHTML = `
      <div class="row">
        <span class="name"></span>
        <span class="badge ${r.status}">${r.status}</span>
      </div>
      <pre></pre>
    `;
    item.querySelector('.name').textContent = r.name;
    item.querySelector('pre').textContent = r.detail;
    resultsList.appendChild(item);
  }

  suggestionsList.innerHTML = '';
  for (const s of data.suggestions) {
    const li = document.createElement('li');
    li.textContent = s;
    suggestionsList.appendChild(li);
  }

  resultsSection.hidden = false;
  lastReport = data;
}

const HISTORY_KEY = 'netdiag_history';
const MAX_HISTORY = 500;

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

function saveHistory(list) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
  } catch {
    // storage unavailable — history just won't persist this session
  }
}

function addToHistory(report) {
  const history = loadHistory();
  history.unshift({
    id: Date.now() + '-' + Math.random().toString(36).slice(2),
    ...report,
  });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  saveHistory(history);
}

async function runDiagnostics() {
  const target = targetInput.value.trim();
  showError('');

  if (!NetDiag) {
    showError('Native diagnostics plugin not available on this platform.');
    return;
  }

  if (!isValidTarget(target)) {
    showError('Enter a valid IPv4/IPv6 address or FQDN (e.g. 8.8.8.8 or example.com).');
    return;
  }

  const checks = selectedChecks();
  if (checks.length === 0) {
    showError('Select at least one check.');
    return;
  }

  runBtn.disabled = true;
  spinner.hidden = false;
  resultsSection.hidden = true;

  try {
    const customPorts = customPortsInput.value.trim();
    const startedAt = Date.now();
    const [results, environment] = await Promise.all([
      Promise.all(checks.map(c => runCheck(c, target, customPorts))),
      getDeviceContext(),
    ]);
    const suggestions = analyze(results);
    const report = {
      target,
      port: customPorts || null,
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      results,
      suggestions,
      metrics: buildMetrics(results),
      overallStatus: overallStatus(results),
      environment,
    };
    renderResults(report);
    addToHistory(report);
  } catch (e) {
    showError('Diagnostics failed: ' + (e.message || e));
  } finally {
    runBtn.disabled = false;
    spinner.hidden = true;
  }
}

function buildReportText(data) {
  const lines = [];
  lines.push('NetDiag AI - Troubleshooting Report');
  lines.push('='.repeat(40));
  lines.push(`Target: ${data.target}`);
  lines.push(`Generated: ${data.timestamp}`);
  lines.push('');
  for (const r of data.results) {
    lines.push(`[${r.status}] ${r.name}`);
    lines.push('-'.repeat(40));
    lines.push(r.detail);
    lines.push('');
  }
  lines.push('Suggested Next Steps');
  lines.push('='.repeat(40));
  for (const s of data.suggestions) {
    lines.push(`- ${s}`);
  }
  return lines.join('\n');
}

async function exportReport() {
  if (!lastReport) return;
  const text = buildReportText(lastReport);
  if (navigator.share) {
    try {
      await navigator.share({ title: 'NetDiag AI Report', text });
      return;
    } catch (e) {
      // fall through to clipboard
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    showError('');
    alert('Report copied to clipboard.');
  } catch (e) {
    alert(text);
  }
}

function buildReportPdf(data) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const marginX = 10;
  const pageBottom = 280;
  let y = 15;

  function ensureSpace(lineHeight) {
    if (y > pageBottom - lineHeight) {
      doc.addPage();
      y = 15;
    }
  }

  doc.setFontSize(16);
  doc.text('NetDiag AI — Troubleshooting Report', marginX, y); y += 9;
  doc.setFontSize(10);
  doc.text(`Target: ${data.target}`, marginX, y); y += 6;
  doc.text(`Generated: ${new Date(data.timestamp).toLocaleString()}`, marginX, y); y += 6;
  if (data.overallStatus) { doc.text(`Overall Status: ${data.overallStatus}`, marginX, y); y += 6; }
  if (data.durationMs != null) { doc.text(`Run duration: ${(data.durationMs / 1000).toFixed(1)}s`, marginX, y); y += 6; }

  const env = data.environment;
  if (env) {
    y += 2;
    doc.setFontSize(11);
    doc.text('Environment', marginX, y); y += 5;
    doc.setFontSize(9);
    const envLines = [
      env.connectionType ? `Connection: ${env.connectionType}${env.vpnActive ? ' (+ VPN)' : ''}` : null,
      env.localIp ? `Local IP: ${env.localIp}` : null,
      env.gatewayIp ? `Gateway: ${env.gatewayIp}` : null,
      env.privateDnsMode ? `Private DNS: ${env.privateDnsMode}` : null,
      env.deviceModel ? `Device: ${env.deviceModel}` : null,
      env.androidVersion ? `Android: ${env.androidVersion}` : null,
      env.appVersion ? `App version: ${env.appVersion}` : null,
    ].filter(Boolean);
    for (const line of envLines) {
      ensureSpace(5);
      doc.text(line, marginX + 2, y); y += 5;
    }
  }
  y += 3;

  for (const r of data.results) {
    ensureSpace(10);
    doc.setFontSize(12);
    doc.text(`[${r.status}] ${r.name}`, marginX, y); y += 6;
    doc.setFontSize(9);
    const lines = doc.splitTextToSize(r.detail || '(no detail)', 190);
    for (const line of lines) {
      ensureSpace(5);
      doc.text(line, marginX + 2, y); y += 5;
    }
    y += 4;
  }

  ensureSpace(10);
  doc.setFontSize(12);
  doc.text('Suggested Next Steps', marginX, y); y += 6;
  doc.setFontSize(9);
  for (const s of data.suggestions) {
    const lines = doc.splitTextToSize('- ' + s, 190);
    for (const line of lines) {
      ensureSpace(5);
      doc.text(line, marginX + 2, y); y += 5;
    }
  }

  return doc;
}

async function downloadPdfReport() {
  if (!lastReport) return;
  if (typeof window.jspdf === 'undefined') {
    alert('PDF library not available.');
    return;
  }
  const doc = buildReportPdf(lastReport);
  const filename = `netdiag-report-${lastReport.target.replace(/[^a-z0-9.-]/gi, '_')}.pdf`;

  if (NetDiag && NetDiag.shareFile) {
    try {
      const dataUri = doc.output('datauristring');
      const base64 = dataUri.split(',')[1];
      await NetDiag.shareFile({ filename, base64, mimeType: 'application/pdf' });
      return;
    } catch (e) {
      showError('Could not share PDF: ' + (e.message || e));
      return;
    }
  }

  // Non-native (plain browser) fallback
  try {
    const blob = doc.output('blob');
    const file = new File([blob], filename, { type: 'application/pdf' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: 'NetDiag AI Report' });
      return;
    }
  } catch (e) {
    // fall through to direct save
  }
  doc.save(filename);
}

runBtn.addEventListener('click', runDiagnostics);
exportBtn.addEventListener('click', exportReport);
downloadPdfBtn.addEventListener('click', downloadPdfReport);
targetInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runDiagnostics();
});

// --- Tabs ---

const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanels = {
  diagnose: document.getElementById('tab-diagnose'),
  history: document.getElementById('tab-history'),
  dashboard: document.getElementById('tab-dashboard'),
  monitor: document.getElementById('tab-monitor'),
  traffic: document.getElementById('tab-traffic'),
  terminal: document.getElementById('tab-terminal'),
};

async function showTab(name) {
  for (const btn of tabButtons) btn.classList.toggle('active', btn.dataset.tab === name);
  for (const [key, panel] of Object.entries(tabPanels)) panel.hidden = key !== name;
  if (name === 'history') { await drainAndMergeBackgroundResults(); renderHistoryList(); }
  if (name === 'dashboard') { await drainAndMergeBackgroundResults(); renderDashboard(); }
  if (name === 'monitor') { renderMonitorTab(); }
  if (name === 'traffic') { startLiveTraffic(); renderUsageSummary(); } else { stopLiveTraffic(); }
  if (name === 'terminal') { terminalInput.focus(); }
}

for (const btn of tabButtons) {
  btn.addEventListener('click', () => showTab(btn.dataset.tab));
}

// --- History ---

const historyList = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

function renderHistoryList() {
  const history = loadHistory();
  if (history.length === 0) {
    historyList.innerHTML = '<p class="empty-state">No runs yet. Diagnostics you run will show up here.</p>';
    return;
  }
  historyList.innerHTML = '';
  for (const h of history) {
    const item = document.createElement('div');
    item.className = 'list-item';
    const status = h.overallStatus || overallStatus(h.results);
    const m = h.metrics || {};
    const summaryParts = [];
    if (m.avgLatencyMs != null) summaryParts.push(`${m.avgLatencyMs.toFixed(1)} ms avg`);
    if (m.packetLossPct != null) summaryParts.push(`${m.packetLossPct}% loss`);
    if (m.dnsResponseMs != null) summaryParts.push(`DNS ${m.dnsResponseMs.toFixed(0)} ms`);
    item.innerHTML = `
      <div class="row">
        <strong></strong>
        <span class="badge ${status}">${status}</span>
      </div>
      <div class="meta"></div>
      <div class="meta summary-line"></div>
    `;
    item.querySelector('strong').textContent = h.target;
    item.querySelector('.meta').textContent = new Date(h.timestamp).toLocaleString();
    item.querySelector('.summary-line').textContent = summaryParts.join(' · ') || 'No metrics captured for this run';
    item.addEventListener('click', () => {
      showTab('diagnose');
      renderResults(h);
    });
    historyList.appendChild(item);
  }
}

clearHistoryBtn.addEventListener('click', () => {
  if (!confirm('Clear all diagnostic history?')) return;
  saveHistory([]);
  renderHistoryList();
});

const exportCsvBtn = document.getElementById('exportCsvBtn');

function csvEscape(v) {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function exportHistoryCsv() {
  const history = loadHistory();
  if (history.length === 0) {
    alert('No history to export yet.');
    return;
  }
  const headers = ['target', 'port', 'timestamp', 'overallStatus', 'durationMs', 'avgLatencyMs', 'minLatencyMs',
    'maxLatencyMs', 'jitterMs', 'packetLossPct', 'dnsResponseMs', 'resolvedIp', 'hopCount', 'sslDaysUntilExpiry',
    'connectionType', 'vpnActive', 'localIp', 'gatewayIp', 'privateDnsMode', 'deviceModel', 'androidVersion', 'appVersion'];
  const rows = [headers.join(',')];
  for (const h of history) {
    const m = h.metrics || {};
    const env = h.environment || {};
    rows.push(headers.map(f => csvEscape(f in m ? m[f] : (f in env ? env[f] : h[f]))).join(','));
  }
  const csv = rows.join('\n');
  const filename = `netdiag-history-${new Date().toISOString().slice(0, 10)}.csv`;

  if (NetDiag && NetDiag.shareFile) {
    try {
      const base64 = btoa(unescape(encodeURIComponent(csv)));
      await NetDiag.shareFile({ filename, base64, mimeType: 'text/csv' });
      return;
    } catch (e) {
      showError('Could not share CSV: ' + (e.message || e));
      return;
    }
  }
  try {
    await navigator.clipboard.writeText(csv);
    alert('CSV copied to clipboard.');
  } catch (e) {
    alert(csv);
  }
}

exportCsvBtn.addEventListener('click', exportHistoryCsv);

// --- Dashboard (Phase 2 + Phase 3 comparison/insights, with time-range filter) ---

let dashboardRange = '7d';
let latencyChartInstance = null;
let lossChartInstance = null;

const DASHBOARD_RANGE_LABELS = {
  '15m': 'Last 15 Minutes',
  '1h': 'Last 1 Hour',
  '6h': 'Last 6 Hours',
  '12h': 'Last 12 Hours',
  '24h': 'Last 24 Hours',
  '7d': 'Last 7 Days',
  '30d': 'Last 30 Days',
  all: 'All Time',
};

const SUB_DAY_RANGES = new Set(['15m', '1h', '6h', '12h', '24h']);

function avgNum(arr) {
  return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
}

function entryStatus(h) {
  return h.overallStatus || overallStatus(h.results || []);
}

function fieldValues(entries, field) {
  return entries.map(e => e.metrics && e.metrics[field]).filter(v => v != null);
}

function buildRollingBuckets(totalMs, bucketMs) {
  const nowMs = Date.now();
  const bucketCount = Math.round(totalMs / bucketMs);
  const buckets = [];
  for (let i = bucketCount - 1; i >= 0; i--) {
    const end = new Date(nowMs - i * bucketMs);
    const start = new Date(nowMs - (i + 1) * bucketMs);
    const label = start.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
    buckets.push({ start, end, label });
  }
  return buckets;
}

function buildDayBuckets(days) {
  const now = new Date();
  const buckets = [];
  for (let i = days - 1; i >= 0; i--) {
    const start = new Date(now);
    start.setHours(0, 0, 0, 0);
    start.setDate(start.getDate() - i);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    buckets.push({ start, end, label: start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) });
  }
  return buckets;
}

function getRangeBuckets(rangeKey, history) {
  switch (rangeKey) {
    case '15m': return buildRollingBuckets(15 * 60000, 60000);            // 15 x 1 min
    case '1h': return buildRollingBuckets(60 * 60000, 5 * 60000);         // 12 x 5 min
    case '6h': return buildRollingBuckets(6 * 3600000, 30 * 60000);       // 12 x 30 min
    case '12h': return buildRollingBuckets(12 * 3600000, 3600000);        // 12 x 1 hr
    case '24h': return buildRollingBuckets(24 * 3600000, 3600000);        // 24 x 1 hr
    case '30d': return buildDayBuckets(30);
    case 'all': {
      let days = 7;
      if (history.length > 0) {
        const oldest = Math.min(...history.map(h => new Date(h.timestamp).getTime()));
        days = Math.min(90, Math.max(7, Math.ceil((Date.now() - oldest) / 86400000) + 1));
      }
      return buildDayBuckets(days);
    }
    case '7d':
    default:
      return buildDayBuckets(7);
  }
}

function bucketEntries(history, buckets) {
  return buckets.map(b => history.filter(h => {
    const t = new Date(h.timestamp).getTime();
    return t >= b.start.getTime() && t < b.end.getTime();
  }));
}

function renderDashboard() {
  const history = loadHistory();
  const buckets = getRangeBuckets(dashboardRange, history);
  const labels = buckets.map(b => b.label);
  const grouped = bucketEntries(history, buckets);

  const avgLatencyByBucket = grouped.map(entries => avgNum(fieldValues(entries, 'avgLatencyMs')));
  const lossByBucket = grouped.map(entries => avgNum(fieldValues(entries, 'packetLossPct')));

  const rangeEntries = grouped.flat();
  const successCount = rangeEntries.filter(e => entryStatus(e) !== 'FAIL').length;
  const failCount = rangeEntries.length - successCount;
  const availabilityPct = rangeEntries.length ? Math.round((successCount / rangeEntries.length) * 100) : null;

  document.getElementById('dashboardRangeLabel').textContent = DASHBOARD_RANGE_LABELS[dashboardRange];
  for (const btn of document.querySelectorAll('#dashboardRangeRow .range-btn')) {
    btn.classList.toggle('active', btn.dataset.range === dashboardRange);
  }

  renderStatTiles({
    avgLatency: fmtMs(avgNum(fieldValues(rangeEntries, 'avgLatencyMs'))),
    packetLoss: fmtPct(avgNum(fieldValues(rangeEntries, 'packetLossPct'))),
    dnsResponse: fmtMs(avgNum(fieldValues(rangeEntries, 'dnsResponseMs'))),
    availability: availabilityPct != null ? availabilityPct + '%' : '—',
    successCount,
    failCount,
  });

  renderLatencyChart(labels, avgLatencyByBucket);
  renderLossChart(labels, lossByBucket);
  renderInsights(rangeEntries, grouped, dashboardRange);
}

for (const btn of document.querySelectorAll('#dashboardRangeRow .range-btn')) {
  btn.addEventListener('click', () => {
    dashboardRange = btn.dataset.range;
    renderDashboard();
  });
}

function fmtMs(v) { return v == null ? '—' : v.toFixed(1) + ' ms'; }
function fmtPct(v) { return v == null ? '—' : v.toFixed(1) + '%'; }

function renderStatTiles(s) {
  const grid = document.getElementById('statGrid');
  grid.innerHTML = '';
  const tiles = [
    ['Avg Latency', s.avgLatency],
    ['Packet Loss', s.packetLoss],
    ['DNS Response', s.dnsResponse],
    ['Availability', s.availability],
    ['Successful Runs', s.successCount],
    ['Failed Runs', s.failCount],
  ];
  for (const [label, value] of tiles) {
    const tile = document.createElement('div');
    tile.className = 'stat-tile';
    tile.innerHTML = '<div class="stat-value"></div><div class="stat-label"></div>';
    tile.querySelector('.stat-value').textContent = value;
    tile.querySelector('.stat-label').textContent = label;
    grid.appendChild(tile);
  }
}

function chartAvailable() {
  return typeof Chart !== 'undefined';
}

function renderLatencyChart(labels, data) {
  const canvas = document.getElementById('latencyChart');
  if (!canvas || !chartAvailable()) return;
  if (latencyChartInstance) latencyChartInstance.destroy();
  latencyChartInstance = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Avg Latency (ms)',
        data,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.15)',
        spanGaps: true,
        tension: 0.3,
        fill: true,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' }, beginAtZero: true },
      },
    },
  });
}

function renderLossChart(labels, data) {
  const canvas = document.getElementById('lossChart');
  if (!canvas || !chartAvailable()) return;
  if (lossChartInstance) lossChartInstance.destroy();
  lossChartInstance = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Packet Loss (%)',
        data,
        backgroundColor: 'rgba(239, 68, 68, 0.55)',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' }, beginAtZero: true, max: 100 },
      },
    },
  });
}

function renderInsights(rangeEntries, grouped, rangeKey) {
  const list = document.getElementById('insightsList');
  list.innerHTML = '';
  const insights = [];

  const isSubDay = SUB_DAY_RANGES.has(rangeKey);
  const unit = isSubDay ? 'period' : 'day';
  const currentLabel = isSubDay ? 'in the most recent period' : 'today';
  const previousLabel = isSubDay ? 'the prior period' : 'yesterday';

  const currentEntries = grouped[grouped.length - 1] || [];
  const previousEntries = grouped[grouped.length - 2] || [];

  const currentLatency = avgNum(fieldValues(currentEntries, 'avgLatencyMs'));
  const previousLatency = avgNum(fieldValues(previousEntries, 'avgLatencyMs'));
  if (currentLatency != null && previousLatency != null && previousLatency > 0) {
    const pctChange = ((currentLatency - previousLatency) / previousLatency) * 100;
    if (Math.abs(pctChange) >= 20) {
      insights.push(`Latency ${pctChange > 0 ? 'increased' : 'decreased'} ${Math.abs(pctChange).toFixed(0)}% ${currentLabel} (${currentLatency.toFixed(1)} ms) compared with ${previousLabel} (${previousLatency.toFixed(1)} ms).`);
    }
  }

  const rollingLatencies = fieldValues(rangeEntries, 'avgLatencyMs');
  if (currentLatency != null && rollingLatencies.length >= 3) {
    const rollingAvg = avgNum(rollingLatencies);
    if (rollingAvg > 0 && currentLatency > rollingAvg * 1.5) {
      insights.push(`The latest ${unit}'s average latency (${currentLatency.toFixed(1)} ms) is well above the period average (${rollingAvg.toFixed(1)} ms) — possible intermittent network issue.`);
    }
  }

  const currentLoss = avgNum(fieldValues(currentEntries, 'packetLossPct'));
  if (currentLoss != null && currentLoss >= 10) {
    insights.push(`Packet loss ${currentLabel} is ${currentLoss.toFixed(0)}% — investigate the network path or local connection.`);
  }

  const failuresNow = currentEntries.filter(e => entryStatus(e) === 'FAIL').length;
  if (failuresNow > 0) {
    insights.push(`${failuresNow} check${failuresNow > 1 ? 's' : ''} failed ${currentLabel} out of ${currentEntries.length} run${currentEntries.length > 1 ? 's' : ''}.`);
  }

  if (insights.length === 0) {
    insights.push(rangeEntries.length
      ? `No unusual changes detected in the selected period.`
      : 'Run some diagnostics to start seeing trends and insights here.');
  }

  for (const s of insights) {
    const li = document.createElement('li');
    li.textContent = s;
    list.appendChild(li);
  }
}

// --- Monitor (Phase 4: background monitoring + alerts) ---

const monitoringToggle = document.getElementById('monitoringToggle');
const monitorError = document.getElementById('monitorError');
const watchTargetInput = document.getElementById('watchTarget');
const watchLatencyInput = document.getElementById('watchLatency');
const watchLossInput = document.getElementById('watchLoss');
const addWatchBtn = document.getElementById('addWatchBtn');
const watchList = document.getElementById('watchList');

function showMonitorError(msg) {
  monitorError.textContent = msg;
  monitorError.hidden = !msg;
}

function backgroundResultToReport(r) {
  const loss = r.packetLossPct ?? 100;
  const status = r.breached ? (loss >= 100 ? 'FAIL' : 'WARNING') : 'PASS';
  const detailParts = [];
  if (r.avgLatencyMs != null) detailParts.push(`Avg latency ${r.avgLatencyMs.toFixed(1)} ms`);
  detailParts.push(`${loss}% packet loss`);
  return {
    id: 'bg-' + r.timestamp + '-' + r.target,
    target: r.target,
    port: null,
    timestamp: new Date(r.timestamp).toISOString(),
    results: [{
      id: 'connectivity',
      name: 'Connectivity (Ping) — background check',
      status,
      detail: detailParts.join(', ') + (r.breached ? '\nThreshold breached — see Monitor tab.' : ''),
      raw: r,
    }],
    suggestions: r.breached
      ? ['Automatic background check detected a threshold breach for this target.']
      : ['Automatic background check — no issues detected.'],
    metrics: {
      avgLatencyMs: r.avgLatencyMs ?? null,
      minLatencyMs: r.minLatencyMs ?? null,
      maxLatencyMs: r.maxLatencyMs ?? null,
      jitterMs: r.jitterMs ?? null,
      packetLossPct: r.packetLossPct ?? null,
      dnsResponseMs: null,
      resolvedIp: null,
      hopCount: null,
      openPorts: null,
      closedPorts: null,
    },
    overallStatus: status,
    background: true,
  };
}

async function drainAndMergeBackgroundResults() {
  if (!NetDiag || !NetDiag.drainBackgroundResults) return;
  try {
    const { results } = await NetDiag.drainBackgroundResults();
    if (!results || results.length === 0) return;
    const history = loadHistory();
    const merged = results.map(backgroundResultToReport).concat(history);
    merged.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    if (merged.length > MAX_HISTORY) merged.length = MAX_HISTORY;
    saveHistory(merged);
  } catch (e) {
    // background drain is best-effort; ignore failures
  }
}

async function renderMonitorTab() {
  showMonitorError('');
  if (!NetDiag) {
    showMonitorError('Native diagnostics plugin not available on this platform.');
    return;
  }
  try {
    const { enabled } = await NetDiag.getMonitoringEnabled();
    monitoringToggle.checked = !!enabled;
  } catch (e) {}
  await renderWatchList();
}

async function renderWatchList() {
  watchList.innerHTML = '';
  if (!NetDiag) return;
  let targets = [];
  try {
    const res = await NetDiag.getWatchedTargets();
    targets = res.targets || [];
  } catch (e) {}
  if (targets.length === 0) {
    watchList.innerHTML = '<p class="empty-state">No targets watched yet. Add one above to start background monitoring.</p>';
    return;
  }
  targets.forEach((t, idx) => {
    const item = document.createElement('div');
    item.className = 'watch-item';
    item.innerHTML = `
      <div class="row">
        <strong></strong>
        <span class="badge ${t.enabled ? 'PASS' : 'WARNING'}"></span>
      </div>
      <div class="meta"></div>
      <div class="actions">
        <button class="toggle-btn"></button>
        <button class="danger remove-btn">Remove</button>
      </div>
    `;
    item.querySelector('strong').textContent = t.target;
    item.querySelector('.badge').textContent = t.enabled ? 'ENABLED' : 'PAUSED';
    item.querySelector('.meta').textContent = `Alert if latency > ${t.latencyThresholdMs} ms or loss ≥ ${t.lossThresholdPct}%`;
    const toggleBtn = item.querySelector('.toggle-btn');
    toggleBtn.textContent = t.enabled ? 'Pause' : 'Resume';
    toggleBtn.addEventListener('click', () => updateWatchedTarget(idx, { enabled: !t.enabled }));
    item.querySelector('.remove-btn').addEventListener('click', () => removeWatchedTarget(idx));
    watchList.appendChild(item);
  });
}

async function updateWatchedTarget(idx, patch) {
  try {
    const res = await NetDiag.getWatchedTargets();
    const targets = res.targets || [];
    if (!targets[idx]) return;
    targets[idx] = { ...targets[idx], ...patch };
    await NetDiag.setWatchedTargets({ targets });
    renderWatchList();
  } catch (e) {
    showMonitorError('Could not update target: ' + (e.message || e));
  }
}

async function removeWatchedTarget(idx) {
  try {
    const res = await NetDiag.getWatchedTargets();
    const targets = res.targets || [];
    targets.splice(idx, 1);
    await NetDiag.setWatchedTargets({ targets });
    renderWatchList();
  } catch (e) {
    showMonitorError('Could not remove target: ' + (e.message || e));
  }
}

addWatchBtn.addEventListener('click', async () => {
  showMonitorError('');
  const target = watchTargetInput.value.trim();
  if (!isValidTarget(target)) {
    showMonitorError('Enter a valid IPv4/IPv6 address or FQDN.');
    return;
  }
  const latencyThresholdMs = Number(watchLatencyInput.value) || 300;
  const lossThresholdPct = Number(watchLossInput.value) || 20;
  try {
    const res = await NetDiag.getWatchedTargets();
    const targets = res.targets || [];
    targets.push({ target, latencyThresholdMs, lossThresholdPct, enabled: true });
    await NetDiag.setWatchedTargets({ targets });
    watchTargetInput.value = '';
    renderWatchList();
  } catch (e) {
    showMonitorError('Could not add target: ' + (e.message || e));
  }
});

monitoringToggle.addEventListener('change', async () => {
  showMonitorError('');
  const wantEnabled = monitoringToggle.checked;
  if (!NetDiag) {
    monitoringToggle.checked = false;
    showMonitorError('Native diagnostics plugin not available.');
    return;
  }
  try {
    if (wantEnabled) {
      const perm = await NetDiag.ensureNotificationPermission();
      if (!perm.granted) {
        monitoringToggle.checked = false;
        showMonitorError("Notification permission denied — alerts won't be shown, so monitoring was not enabled. Allow notifications for NetDiag AI in Android settings and try again.");
        return;
      }
    }
    await NetDiag.setMonitoringEnabled({ enabled: wantEnabled });
  } catch (e) {
    monitoringToggle.checked = !wantEnabled;
    showMonitorError('Could not update monitoring: ' + (e.message || e));
  }
});

// --- Traffic monitor ---

const liveDownSpeed = document.getElementById('liveDownSpeed');
const liveUpSpeed = document.getElementById('liveUpSpeed');
const bootRx = document.getElementById('bootRx');
const bootTx = document.getElementById('bootTx');
const usageAccessGate = document.getElementById('usageAccessGate');
const grantUsageAccessBtn = document.getElementById('grantUsageAccessBtn');
const usageTotalsGrid = document.getElementById('usageTotalsGrid');
const appUsageList = document.getElementById('appUsageList');

let trafficRange = 'today';
let trafficPollHandle = null;
let lastTrafficSample = null;

function formatBytes(n) {
  if (n == null || isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function formatSpeed(bytesPerSec) {
  return formatBytes(bytesPerSec) + '/s';
}

async function pollLiveTraffic() {
  if (!NetDiag || !NetDiag.getTrafficSnapshot) return;
  try {
    const snap = await NetDiag.getTrafficSnapshot();
    const now = Date.now();
    bootRx.textContent = formatBytes(snap.totalRxBytes);
    bootTx.textContent = formatBytes(snap.totalTxBytes);
    if (lastTrafficSample) {
      const dt = (now - lastTrafficSample.t) / 1000;
      if (dt > 0) {
        const downSpeed = Math.max(0, (snap.totalRxBytes - lastTrafficSample.rx) / dt);
        const upSpeed = Math.max(0, (snap.totalTxBytes - lastTrafficSample.tx) / dt);
        liveDownSpeed.textContent = formatSpeed(downSpeed);
        liveUpSpeed.textContent = formatSpeed(upSpeed);
      }
    }
    lastTrafficSample = { t: now, rx: snap.totalRxBytes, tx: snap.totalTxBytes };
  } catch (e) {
    // best-effort live meter; ignore transient failures
  }
}

function startLiveTraffic() {
  if (trafficPollHandle) return;
  lastTrafficSample = null;
  pollLiveTraffic();
  trafficPollHandle = setInterval(pollLiveTraffic, 1500);
}

function stopLiveTraffic() {
  if (trafficPollHandle) {
    clearInterval(trafficPollHandle);
    trafficPollHandle = null;
  }
}

function trafficRangeBounds(rangeKey) {
  const end = Date.now();
  const now = new Date();
  let start;
  if (rangeKey === 'today') {
    const d = new Date(now); d.setHours(0, 0, 0, 0);
    start = d.getTime();
  } else if (rangeKey === '7d') {
    start = end - 7 * 86400000;
  } else {
    start = end - 30 * 86400000;
  }
  return { start, end };
}

async function renderUsageSummary() {
  if (!NetDiag || !NetDiag.hasUsageAccess) return;
  for (const btn of document.querySelectorAll('#trafficRangeRow .range-btn')) {
    btn.classList.toggle('active', btn.dataset.range === trafficRange);
  }
  try {
    const { granted } = await NetDiag.hasUsageAccess();
    usageAccessGate.hidden = !!granted;
  } catch (e) {
    usageAccessGate.hidden = false;
  }

  const { start, end } = trafficRangeBounds(trafficRange);
  usageTotalsGrid.innerHTML = '';
  appUsageList.innerHTML = '<p class="empty-state">Loading…</p>';
  try {
    const summary = await NetDiag.getUsageSummary({ startMs: start, endMs: end });
    const tiles = [
      ['Total Received', formatBytes(summary.totalRxBytes)],
      ['Total Sent', formatBytes(summary.totalTxBytes)],
    ];
    for (const [label, value] of tiles) {
      const tile = document.createElement('div');
      tile.className = 'stat-tile';
      tile.innerHTML = '<div class="stat-value"></div><div class="stat-label"></div>';
      tile.querySelector('.stat-value').textContent = value;
      tile.querySelector('.stat-label').textContent = label;
      usageTotalsGrid.appendChild(tile);
    }

    const apps = (summary.apps || []).slice().sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes));
    appUsageList.innerHTML = '';
    if (apps.length === 0) {
      appUsageList.innerHTML = '<p class="empty-state">' +
        (summary.hasUsageAccess ? 'No per-app usage recorded for this period yet.' : 'Grant Usage Access above to see a per-app breakdown.') +
        '</p>';
    } else {
      for (const a of apps) {
        const item = document.createElement('div');
        item.className = 'app-usage-item';
        item.innerHTML = '<span class="app-label"></span><span class="app-bytes"></span>';
        item.querySelector('.app-label').textContent = a.label;
        item.querySelector('.app-bytes').textContent = `↓ ${formatBytes(a.rxBytes)}  ↑ ${formatBytes(a.txBytes)}`;
        appUsageList.appendChild(item);
      }
    }
  } catch (e) {
    appUsageList.innerHTML = '<p class="empty-state">Could not load usage data on this device.</p>';
  }
}

for (const btn of document.querySelectorAll('#trafficRangeRow .range-btn')) {
  btn.addEventListener('click', () => {
    trafficRange = btn.dataset.range;
    renderUsageSummary();
  });
}

grantUsageAccessBtn.addEventListener('click', async () => {
  if (NetDiag && NetDiag.openUsageAccessSettings) {
    try { await NetDiag.openUsageAccessSettings(); } catch (e) {}
  }
});

// --- Terminal (sandboxed network command interpreter) ---

const terminalOutput = document.getElementById('terminalOutput');
const terminalInput = document.getElementById('terminalInput');
const clearTerminalBtn = document.getElementById('clearTerminalBtn');

function termPrint(html) {
  const line = document.createElement('div');
  line.innerHTML = html;
  terminalOutput.appendChild(line);
  terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function termEscape(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

async function runTerminalInput() {
  const cmdText = terminalInput.value;
  if (!cmdText.trim()) return;
  terminalInput.value = '';
  termPrint(`<span class="term-cmd">$ ${termEscape(cmdText)}</span>`);

  const firstWord = cmdText.trim().split(/\s+/)[0].toLowerCase();
  if (firstWord === 'clear') {
    terminalOutput.innerHTML = '';
    return;
  }
  if (firstWord === 'help') {
    termPrint(`<pre>${termEscape(
      "Available commands:\n" +
      "  ping <host> [-c N]   ping6 <host>\n" +
      "  traceroute <host>    tracepath <host>\n" +
      "  nslookup <host>      dig <host>\n" +
      "  ifconfig / ip        netstat\n" +
      "  whoami  hostname  date  uptime  echo <text>  clear\n\n" +
      "This is a sandboxed subset of commands for network troubleshooting — not a root shell."
    )}</pre>`);
    return;
  }
  if (!NetDiag || !NetDiag.runTerminalCommand) {
    termPrint('<span class="term-err">Native terminal plugin not available on this platform.</span>');
    return;
  }
  try {
    const { output } = await NetDiag.runTerminalCommand({ input: cmdText });
    termPrint(`<pre>${termEscape(output || '')}</pre>`);
  } catch (e) {
    termPrint(`<span class="term-err">${termEscape('Error: ' + (e.message || e))}</span>`);
  }
}

terminalInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runTerminalInput();
});

clearTerminalBtn.addEventListener('click', () => {
  terminalOutput.innerHTML = '';
});

termPrint('<span>NetDiag AI Terminal — type <b>help</b> to see available commands.</span>');

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    drainAndMergeBackgroundResults();
    if (!tabPanels.traffic.hidden) startLiveTraffic();
  } else {
    stopLiveTraffic();
  }
});

drainAndMergeBackgroundResults();
