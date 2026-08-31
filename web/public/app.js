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
const checkboxes = document.querySelectorAll('.checks input[type="checkbox"]');
const sshCheckbox = document.getElementById('sshCheckbox');
const sshFields = document.getElementById('sshFields');
const sshUsername = document.getElementById('sshUsername');
const sshPassword = document.getElementById('sshPassword');
const sshPort = document.getElementById('sshPort');

let lastReport = null;

sshCheckbox.addEventListener('change', () => {
  sshFields.hidden = !sshCheckbox.checked;
});

function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.hidden = !msg;
}

function selectedChecks() {
  return Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value);
}

function renderResults(data) {
  resultTarget.textContent = data.target;
  resultsList.innerHTML = '';

  for (const r of data.results) {
    const item = document.createElement('div');
    item.className = 'result-item';
    item.innerHTML = `
      <div class="row">
        <span class="name">${r.name}</span>
        <span class="badge ${r.status}">${r.status}</span>
      </div>
      <pre></pre>
    `;
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

async function runDiagnostics() {
  const target = targetInput.value.trim();
  showError('');

  if (!target) {
    showError('Please enter an IP address or FQDN.');
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

  const customPorts = customPortsInput.value
    .split(',')
    .map(p => p.trim())
    .filter(Boolean);

  let sshCreds;
  if (checks.includes('ssh')) {
    sshCreds = {
      username: sshUsername.value.trim(),
      password: sshPassword.value,
      port: parseInt(sshPort.value.trim(), 10) || 22,
    };
  }

  try {
    const res = await fetch('/api/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, checks, customPorts, sshCreds }),
    });
    const data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Diagnostics failed.');
      return;
    }

    renderResults(data);
  } catch (e) {
    showError('Could not reach the diagnostics server. Is it running?');
  } finally {
    runBtn.disabled = false;
    spinner.hidden = true;
    sshPassword.value = '';
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

function exportReport() {
  if (!lastReport) return;
  const text = buildReportText(lastReport);
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const safeTarget = lastReport.target.replace(/[^a-zA-Z0-9.-]/g, '_');
  a.href = url;
  a.download = `netdiag-report-${safeTarget}-${Date.now()}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

runBtn.addEventListener('click', runDiagnostics);
exportBtn.addEventListener('click', exportReport);
targetInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runDiagnostics();
});

// --- Tabs ---

const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanels = {
  diagnose: document.getElementById('tab-diagnose'),
  history: document.getElementById('tab-history'),
  monitors: document.getElementById('tab-monitors'),
};
let monitorsPollTimer = null;

function showTab(name) {
  for (const btn of tabButtons) btn.classList.toggle('active', btn.dataset.tab === name);
  for (const [key, panel] of Object.entries(tabPanels)) panel.hidden = key !== name;

  if (monitorsPollTimer) { clearInterval(monitorsPollTimer); monitorsPollTimer = null; }
  if (name === 'history') loadHistory();
  if (name === 'monitors') {
    loadMonitors();
    monitorsPollTimer = setInterval(loadMonitors, 15000);
  }
}

for (const btn of tabButtons) {
  btn.addEventListener('click', () => showTab(btn.dataset.tab));
}

// --- History ---

const historyList = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

async function loadHistory() {
  historyList.innerHTML = '<p class="empty-state">Loading…</p>';
  try {
    const res = await fetch('/api/history');
    const history = await res.json();
    if (history.length === 0) {
      historyList.innerHTML = '<p class="empty-state">No runs yet. Diagnostics you run will show up here.</p>';
      return;
    }
    historyList.innerHTML = '';
    for (const h of history) {
      const item = document.createElement('div');
      item.className = 'list-item';
      const badges = h.summary.map(s => `<span class="badge ${s.status}">${s.status}</span>`).join(' ');
      item.innerHTML = `
        <div class="row">
          <strong>${h.target}</strong>
          <span class="meta">${new Date(h.timestamp).toLocaleString()}</span>
        </div>
        <div class="meta">${h.source === 'manual' ? 'Manual run' : 'Monitor run'}</div>
        <div class="badge-row">${badges}</div>
      `;
      item.style.cursor = 'pointer';
      item.addEventListener('click', () => viewHistoryDetail(h.id));
      historyList.appendChild(item);
    }
  } catch (e) {
    historyList.innerHTML = '<p class="empty-state">Could not load history.</p>';
  }
}

async function viewHistoryDetail(id) {
  const res = await fetch(`/api/history/${id}`);
  if (!res.ok) return;
  const record = await res.json();
  showTab('diagnose');
  renderResults(record);
}

clearHistoryBtn.addEventListener('click', async () => {
  if (!confirm('Clear all diagnostic history?')) return;
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
});

// --- Monitors ---

const monitorTargetInput = document.getElementById('monitorTarget');
const monitorIntervalInput = document.getElementById('monitorInterval');
const addMonitorBtn = document.getElementById('addMonitorBtn');
const monitorErrorMsg = document.getElementById('monitorErrorMsg');
const monitorsList = document.getElementById('monitorsList');
const alertsList = document.getElementById('alertsList');

async function loadMonitors() {
  try {
    const [monitorsRes, alertsRes] = await Promise.all([fetch('/api/monitors'), fetch('/api/alerts')]);
    const monitors = await monitorsRes.json();
    const alerts = await alertsRes.json();

    monitorsList.innerHTML = monitors.length === 0
      ? '<p class="empty-state">No monitors yet. Add a target above to check it automatically on a schedule.</p>'
      : '';
    for (const m of monitors) {
      const item = document.createElement('div');
      item.className = 'list-item';
      item.innerHTML = `
        <div class="row">
          <strong>${m.target}</strong>
          ${m.lastStatus ? `<span class="badge ${m.lastStatus}">${m.lastStatus}</span>` : '<span class="meta">not yet run</span>'}
        </div>
        <div class="meta">Every ${m.intervalMinutes} min · last run: ${m.lastRunAt ? new Date(m.lastRunAt).toLocaleString() : 'never'}</div>
        <button data-id="${m.id}">Remove</button>
      `;
      item.querySelector('button').addEventListener('click', async () => {
        await fetch(`/api/monitors/${m.id}`, { method: 'DELETE' });
        loadMonitors();
      });
      monitorsList.appendChild(item);
    }

    alertsList.innerHTML = alerts.length === 0
      ? '<p class="empty-state">No alerts yet. You\'ll see status-change alerts here once a monitored target changes state.</p>'
      : '';
    for (const a of alerts) {
      const item = document.createElement('div');
      item.className = 'list-item';
      item.innerHTML = `
        <div class="row">
          <strong>${a.target}</strong>
          <span class="meta">${new Date(a.timestamp).toLocaleString()}</span>
        </div>
        <div>${a.message}</div>
      `;
      alertsList.appendChild(item);
    }
  } catch (e) {
    monitorsList.innerHTML = '<p class="empty-state">Could not load monitors.</p>';
  }
}

addMonitorBtn.addEventListener('click', async () => {
  const target = monitorTargetInput.value.trim();
  const intervalMinutes = parseInt(monitorIntervalInput.value.trim(), 10) || 15;
  monitorErrorMsg.hidden = true;

  if (!target) {
    monitorErrorMsg.textContent = 'Enter a target to monitor.';
    monitorErrorMsg.hidden = false;
    return;
  }

  const res = await fetch('/api/monitors', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, intervalMinutes }),
  });
  const data = await res.json();

  if (!res.ok) {
    monitorErrorMsg.textContent = data.error || 'Could not add monitor.';
    monitorErrorMsg.hidden = false;
    return;
  }

  monitorTargetInput.value = '';
  monitorIntervalInput.value = '';
  loadMonitors();
});
