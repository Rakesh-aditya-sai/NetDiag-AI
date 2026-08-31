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
      default: throw new Error('Unknown check: ' + id);
    }
    return { name: CHECK_LABELS[id], status: result.status, detail: result.detail };
  } catch (e) {
    return { name: CHECK_LABELS[id], status: 'FAIL', detail: 'Check failed to run: ' + (e.message || e) };
  }
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

function renderResults(data) {
  resultTarget.textContent = data.target;
  resultsList.innerHTML = '';

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
    const results = await Promise.all(checks.map(c => runCheck(c, target, customPorts)));
    const suggestions = analyze(results);
    renderResults({ target, timestamp: new Date().toISOString(), results, suggestions });
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

runBtn.addEventListener('click', runDiagnostics);
exportBtn.addEventListener('click', exportReport);
targetInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runDiagnostics();
});
