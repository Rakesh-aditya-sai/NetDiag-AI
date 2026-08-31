const express = require('express');
const path = require('path');
const fs = require('fs');
const net = require('net');
const dgram = require('dgram');
const dnsSync = require('dns');
const dns = dnsSync.promises;
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { Client: SSHClient } = require('ssh2');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 4200;
const COMMON_PORTS = [80, 443, 22, 3389, 53, 3306];

const DATA_DIR = path.join(process.cwd(), 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const MONITORS_FILE = path.join(DATA_DIR, 'monitors.json');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
const MAX_HISTORY = 200;
const MAX_ALERTS = 200;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function appendHistory(record) {
  const history = readJson(HISTORY_FILE, []);
  history.unshift(record);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  writeJson(HISTORY_FILE, history);
}

function appendAlert(alert) {
  const alerts = readJson(ALERTS_FILE, []);
  alerts.unshift(alert);
  if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  writeJson(ALERTS_FILE, alerts);
}

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$/;

function fmtAddr(ip, port) {
  const host = net.isIPv6(ip) ? `[${ip}]` : ip;
  return port != null ? `${host}:${port}` : host;
}

function isValidTarget(target) {
  if (typeof target !== 'string' || target.length === 0 || target.length > 253) return false;
  if (target.startsWith('-')) return false;
  if (net.isIP(target) !== 0) return true;
  if (IPV4_RE.test(target)) return true;
  return HOSTNAME_RE.test(target);
}

function runCommand(cmd, args, timeoutMs = 15000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs }, (error, stdout, stderr) => {
      resolve({ error, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function getLocalAddressFor(target) {
  return new Promise((resolve) => {
    const type = net.isIPv6(target) ? 'udp6' : 'udp4';
    const socket = dgram.createSocket(type);
    socket.connect(53, target, () => {
      try {
        resolve(socket.address().address);
      } catch {
        resolve(null);
      } finally {
        socket.close();
      }
    });
    socket.once('error', () => { resolve(null); try { socket.close(); } catch {} });
  });
}

async function checkConnectivity(target) {
  const [{ error, stdout }, localAddr] = await Promise.all([
    runCommand('ping', ['-c', '4', '-W', '2', target]),
    getLocalAddressFor(target),
  ]);
  const lossMatch = stdout.match(/(\d+)% packet loss/);
  const loss = lossMatch ? parseInt(lossMatch[1], 10) : 100;
  let status = 'FAIL';
  if (loss === 0) status = 'PASS';
  else if (loss < 100) status = 'WARNING';
  const addrLine = localAddr ? `Source: ${localAddr}  →  Destination: ${target}\n` : '';
  return {
    name: 'Connectivity (Ping)',
    status,
    detail: addrLine + (stdout.trim() || (error ? error.message : 'No response')),
  };
}

async function checkDns(target) {
  const resolvers = dnsSync.getServers();
  const resolverLine = `DNS server(s) queried: ${resolvers.join(', ') || 'unknown'}`;
  try {
    const isIp = net.isIP(target) !== 0;
    if (isIp) {
      try {
        const hosts = await dns.reverse(target);
        return { name: 'DNS Resolution', status: 'PASS', detail: `${resolverLine}\nReverse DNS: ${target} → ${hosts.join(', ')}` };
      } catch {
        return { name: 'DNS Resolution', status: 'WARNING', detail: `${resolverLine}\nTarget is an IP with no reverse DNS (PTR) record — this is often normal.` };
      }
    }
    const result = await dns.lookup(target, { all: true });
    const addrs = result.map(r => `${r.address} (IPv${r.family})`).join(', ');
    return { name: 'DNS Resolution', status: 'PASS', detail: `${resolverLine}\n${target} resolved to: ${addrs}` };
  } catch (e) {
    return { name: 'DNS Resolution', status: 'FAIL', detail: `${resolverLine}\nCould not resolve hostname: ${e.message}` };
  }
}

function checkPort(target, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open) => {
      if (settled) return;
      settled = true;
      const result = { port, open };
      if (open) {
        result.localAddress = socket.localAddress;
        result.localPort = socket.localPort;
        result.remoteAddress = socket.remoteAddress;
        result.remotePort = socket.remotePort;
      }
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, target);
  });
}

function parseCustomPorts(customPorts) {
  if (!customPorts) return [];
  const raw = Array.isArray(customPorts) ? customPorts : String(customPorts).split(',');
  const ports = [];
  for (const p of raw) {
    const n = parseInt(String(p).trim(), 10);
    if (Number.isInteger(n) && n >= 1 && n <= 65535) ports.push(n);
  }
  return ports;
}

async function checkFirewall(target, customPorts) {
  const ports = Array.from(new Set([...COMMON_PORTS, ...parseCustomPorts(customPorts)]));
  const results = await Promise.all(ports.map(p => checkPort(target, p)));
  const openPorts = results.filter(r => r.open).map(r => r.port);
  const closedPorts = results.filter(r => !r.open).map(r => r.port);
  let status = 'WARNING';
  if (openPorts.length > 0) status = 'PASS';

  const lines = results.map(r => r.open
    ? `Port ${r.port}: OPEN     src ${fmtAddr(r.localAddress, r.localPort)}  →  dst ${fmtAddr(r.remoteAddress, r.remotePort)}`
    : `Port ${r.port}: CLOSED/FILTERED  →  dst ${fmtAddr(target, r.port)}`
  );

  return {
    name: 'Firewall / Port Check',
    status,
    detail: `Open: [${openPorts.join(', ') || 'none'}]  Closed/Filtered: [${closedPorts.join(', ')}]\n\n${lines.join('\n')}`,
  };
}

async function checkTraceroute(target) {
  const { error, stdout, stderr } = await runCommand('stdbuf', ['-oL', 'tracepath', '-n', '-4', '-m', '15', target], 10000);
  const output = (stdout || stderr).trim();
  let status = 'WARNING';
  if (/reached/i.test(output)) status = 'PASS';
  else if (!output) status = 'FAIL';
  return {
    name: 'Traceroute',
    status,
    detail: output || (error ? error.message : 'No trace data'),
  };
}

function httpProbe(target, port, useTls) {
  return new Promise((resolve) => {
    const lib = useTls ? https : http;
    const req = lib.request(
      { host: target, port, path: '/', method: 'HEAD', timeout: 4000, rejectUnauthorized: false },
      (res) => {
        const sock = res.socket;
        resolve({
          ok: true,
          statusCode: res.statusCode,
          localAddress: sock.localAddress,
          localPort: sock.localPort,
          remoteAddress: sock.remoteAddress,
          remotePort: sock.remotePort,
        });
        res.resume();
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.end();
  });
}

function addrLine(r) {
  return `src ${fmtAddr(r.localAddress, r.localPort)}  →  dst ${fmtAddr(r.remoteAddress, r.remotePort)}`;
}

async function checkCloud(target) {
  const httpsResult = await httpProbe(target, 443, true);
  if (httpsResult.ok) {
    return { name: 'Cloud / HTTP(S) Reachability', status: 'PASS', detail: `HTTPS reachable, status ${httpsResult.statusCode}\n${addrLine(httpsResult)}` };
  }
  const httpResult = await httpProbe(target, 80, false);
  if (httpResult.ok) {
    return { name: 'Cloud / HTTP(S) Reachability', status: 'WARNING', detail: `HTTPS failed (${httpsResult.error}); HTTP reachable, status ${httpResult.statusCode}\n${addrLine(httpResult)}` };
  }
  return { name: 'Cloud / HTTP(S) Reachability', status: 'FAIL', detail: `HTTPS failed (${httpsResult.error}); HTTP failed (${httpResult.error})` };
}

function runSshCommand(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      let errOut = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.stderr.on('data', (d) => { errOut += d.toString(); });
      stream.on('close', () => resolve((out || errOut).trim()));
      stream.on('error', reject);
    });
  });
}

async function checkSsh(target, sshCreds) {
  if (!sshCreds || !sshCreds.username || (!sshCreds.password && !sshCreds.privateKey)) {
    return { name: 'SSH Remote Check', status: 'WARNING', detail: 'SSH check skipped — username and a password or private key are required. Credentials are used only for this one request and are never saved.' };
  }
  const port = Number.isInteger(sshCreds.port) ? sshCreds.port : 22;

  return new Promise((resolve) => {
    const conn = new SSHClient();
    const timeout = setTimeout(() => {
      conn.end();
      resolve({ name: 'SSH Remote Check', status: 'FAIL', detail: `SSH connection to ${target}:${port} timed out.` });
    }, 8000);

    conn.on('ready', async () => {
      clearTimeout(timeout);
      try {
        const [uptime, mem, disk, iface] = await Promise.all([
          runSshCommand(conn, 'uptime').catch(e => `(error: ${e.message})`),
          runSshCommand(conn, 'free -m 2>/dev/null || vm_stat 2>/dev/null').catch(e => `(error: ${e.message})`),
          runSshCommand(conn, "df -h / 2>/dev/null").catch(e => `(error: ${e.message})`),
          runSshCommand(conn, "ip -brief addr show 2>/dev/null || ifconfig 2>/dev/null").catch(e => `(error: ${e.message})`),
        ]);
        conn.end();
        const detail = [
          `Connected as ${sshCreds.username}@${target}:${port}`,
          `\n--- uptime / load ---\n${uptime}`,
          `\n--- memory ---\n${mem}`,
          `\n--- disk (/) ---\n${disk}`,
          `\n--- interfaces ---\n${iface}`,
        ].join('\n');
        resolve({ name: 'SSH Remote Check', status: 'PASS', detail });
      } catch (e) {
        conn.end();
        resolve({ name: 'SSH Remote Check', status: 'WARNING', detail: `Connected but a remote command failed: ${e.message}` });
      }
    });

    conn.on('error', (e) => {
      clearTimeout(timeout);
      resolve({ name: 'SSH Remote Check', status: 'FAIL', detail: `SSH connection failed: ${e.message}` });
    });

    const connectOpts = {
      host: target,
      port,
      username: sshCreds.username,
      readyTimeout: 7000,
    };
    if (sshCreds.privateKey) connectOpts.privateKey = sshCreds.privateKey;
    else connectOpts.password = sshCreds.password;

    conn.connect(connectOpts);
  });
}

const CHECKS = {
  connectivity: checkConnectivity,
  dns: checkDns,
  firewall: checkFirewall,
  traceroute: checkTraceroute,
  cloud: checkCloud,
  ssh: checkSsh,
};

function analyze(results) {
  const byName = {};
  for (const r of results) byName[r.name] = r.status;

  const suggestions = [];
  const ping = byName['Connectivity (Ping)'];
  const dnsStatus = byName['DNS Resolution'];
  const fw = byName['Firewall / Port Check'];
  const cloud = byName['Cloud / HTTP(S) Reachability'];

  if (dnsStatus === 'FAIL') {
    suggestions.push('DNS resolution failed. Verify the hostname is correct and that a working DNS server is reachable (check /etc/resolv.conf or DHCP-assigned DNS).');
  }
  if (ping === 'FAIL' && dnsStatus === 'FAIL') {
    suggestions.push('Both DNS and ICMP failed — check basic network path: local routing, VPN/SD-WAN tunnel status, and upstream ISP/link.');
  } else if (ping === 'FAIL' && (dnsStatus === 'PASS' || dnsStatus === 'WARNING')) {
    suggestions.push('The address resolves fine but does not respond to ICMP. This usually means a firewall (host-based or network) is blocking ICMP, or the host is powered off / disconnected.');
  }
  if (ping === 'PASS' && fw === 'WARNING') {
    suggestions.push('Host answers pings but no common service ports are open. If a specific service should be running, check that it is bound and listening, and that firewall rules allow the port.');
  }
  if (cloud === 'FAIL' && ping === 'PASS') {
    suggestions.push('Host is reachable at the network layer but HTTP/HTTPS is not responding — check the web service status and any reverse proxy/load balancer in front of it.');
  }
  if (results.every(r => r.status === 'PASS')) {
    suggestions.push('All checks passed. No further action needed.');
  }
  if (suggestions.length === 0) {
    suggestions.push('Review the individual check details above for anomalies; no clear single root cause pattern was detected.');
  }
  return suggestions;
}

const DEFAULT_CHECKS = ['connectivity', 'dns', 'firewall', 'traceroute', 'cloud'];

async function runDiagnose({ target, checks, customPorts, sshCreds }) {
  const selected = Array.isArray(checks) && checks.length > 0
    ? checks.filter(c => CHECKS[c])
    : DEFAULT_CHECKS;

  const results = await Promise.all(selected.map(c => {
    if (c === 'firewall') return checkFirewall(target, customPorts);
    if (c === 'ssh') return checkSsh(target, sshCreds);
    return CHECKS[c](target);
  }));
  const suggestions = analyze(results);
  return { target, timestamp: new Date().toISOString(), results, suggestions };
}

app.post('/api/diagnose', async (req, res) => {
  const { target, checks, customPorts, sshCreds } = req.body || {};

  if (!isValidTarget(target)) {
    return res.status(400).json({ error: 'Invalid target. Enter a valid IPv4/IPv6 address or FQDN (e.g. 8.8.8.8 or example.com).' });
  }

  const selected = Array.isArray(checks) && checks.length > 0
    ? checks.filter(c => CHECKS[c])
    : DEFAULT_CHECKS;

  if (selected.length === 0) {
    return res.status(400).json({ error: 'No valid checks selected.' });
  }

  try {
    const report = await runDiagnose({ target, checks, customPorts, sshCreds });
    appendHistory({
      id: crypto.randomUUID(),
      target: report.target,
      timestamp: report.timestamp,
      source: 'manual',
      summary: report.results.map(r => ({ name: r.name, status: r.status })),
      results: report.results,
      suggestions: report.suggestions,
    });
    res.json(report);
  } catch (e) {
    res.status(500).json({ error: `Diagnostics failed: ${e.message}` });
  }
});

app.get('/api/history', (req, res) => {
  const history = readJson(HISTORY_FILE, []);
  res.json(history.map(h => ({ id: h.id, target: h.target, timestamp: h.timestamp, source: h.source, summary: h.summary })));
});

app.get('/api/history/:id', (req, res) => {
  const history = readJson(HISTORY_FILE, []);
  const record = history.find(h => h.id === req.params.id);
  if (!record) return res.status(404).json({ error: 'History record not found.' });
  res.json(record);
});

app.delete('/api/history', (req, res) => {
  writeJson(HISTORY_FILE, []);
  res.json({ ok: true });
});

// --- Scheduled monitoring ---

app.get('/api/monitors', (req, res) => {
  res.json(readJson(MONITORS_FILE, []));
});

app.post('/api/monitors', (req, res) => {
  const { target, checks, customPorts, intervalMinutes } = req.body || {};
  if (!isValidTarget(target)) {
    return res.status(400).json({ error: 'Invalid target.' });
  }
  const interval = Number.isFinite(intervalMinutes) && intervalMinutes >= 1 ? intervalMinutes : 15;
  const monitors = readJson(MONITORS_FILE, []);
  const monitor = {
    id: crypto.randomUUID(),
    target,
    checks: Array.isArray(checks) && checks.length > 0 ? checks : DEFAULT_CHECKS,
    customPorts: customPorts || '',
    intervalMinutes: interval,
    createdAt: new Date().toISOString(),
    lastRunAt: null,
    lastStatus: null,
  };
  monitors.push(monitor);
  writeJson(MONITORS_FILE, monitors);
  res.json(monitor);
});

app.delete('/api/monitors/:id', (req, res) => {
  const monitors = readJson(MONITORS_FILE, []);
  const next = monitors.filter(m => m.id !== req.params.id);
  writeJson(MONITORS_FILE, next);
  res.json({ ok: true });
});

app.get('/api/alerts', (req, res) => {
  res.json(readJson(ALERTS_FILE, []));
});

function overallStatus(results) {
  if (results.some(r => r.status === 'FAIL')) return 'FAIL';
  if (results.some(r => r.status === 'WARNING')) return 'WARNING';
  return 'PASS';
}

async function runMonitorTick() {
  const monitors = readJson(MONITORS_FILE, []);
  if (monitors.length === 0) return;
  const now = Date.now();
  let changed = false;

  for (const monitor of monitors) {
    const dueAt = monitor.lastRunAt ? new Date(monitor.lastRunAt).getTime() + monitor.intervalMinutes * 60000 : 0;
    if (now < dueAt) continue;

    try {
      const report = await runDiagnose({ target: monitor.target, checks: monitor.checks, customPorts: monitor.customPorts });
      const status = overallStatus(report.results);

      appendHistory({
        id: crypto.randomUUID(),
        target: report.target,
        timestamp: report.timestamp,
        source: `monitor:${monitor.id}`,
        summary: report.results.map(r => ({ name: r.name, status: r.status })),
        results: report.results,
        suggestions: report.suggestions,
      });

      if (monitor.lastStatus && monitor.lastStatus !== status) {
        appendAlert({
          id: crypto.randomUUID(),
          monitorId: monitor.id,
          target: monitor.target,
          timestamp: report.timestamp,
          previousStatus: monitor.lastStatus,
          newStatus: status,
          message: `${monitor.target}: status changed from ${monitor.lastStatus} to ${status}`,
        });
      }

      monitor.lastStatus = status;
      monitor.lastRunAt = report.timestamp;
      changed = true;
    } catch (e) {
      monitor.lastRunAt = new Date().toISOString();
      monitor.lastStatus = 'FAIL';
      changed = true;
    }
  }

  if (changed) writeJson(MONITORS_FILE, monitors);
}

setInterval(() => { runMonitorTick().catch(() => {}); }, 60000);

app.listen(PORT, '0.0.0.0', () => {
  ensureDataDir();
  console.log(`NetDiag AI running at http://0.0.0.0:${PORT}`);
  runMonitorTick().catch(() => {});
});
