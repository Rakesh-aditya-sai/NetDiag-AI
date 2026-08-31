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

let lastReport = null;

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

  try {
    const res = await fetch('/api/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, checks, customPorts }),
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
