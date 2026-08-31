# NetDiag AI — Network Troubleshooting Assistant

A small web app for support engineers: enter a device's IP or FQDN, pick which checks to run, and get PASS/WARNING/FAIL results plus suggested next steps. Generates a downloadable TAC-ready text report.

## Checks
- Connectivity (ping)
- DNS resolution (forward + reverse, shows the resolver server(s) actually queried)
- Firewall / port check — common ports (80, 443, 22, 3389, 53, 3306) plus any custom ports you add
- Traceroute (IPv4, capped at 15 hops / 10s)
- Cloud / HTTP(S) reachability
- SSH remote check (optional) — enter credentials to pull uptime/memory/disk/interface info directly from the target over SSH; credentials are used only for that one request and are never persisted

Every check result shows the real source and destination IP:port used, not just a pass/fail badge.

## History and monitoring
- **History tab**: every diagnostic run is saved locally (`data/history.json`, gitignored) and viewable/re-openable later.
- **Monitors tab**: add a target to be re-checked automatically on an interval; a status-change (e.g. PASS → FAIL) raises an alert shown in the Alerts list.

## Run

```
cd /home/raki/NetDiagAI/web
npm install
npm start
```

Opens on `http://localhost:4200`. To use from your phone or another device on the same WiFi, allow the port through the firewall once:

```
sudo ufw allow 4200/tcp
```

then browse to `http://<this-PC's-LAN-IP>:4200` (find it with `hostname -I`).

## Windows executable

```
npm run build:win
```

Produces a standalone `dist/NetDiagAI-win.exe` (via `@yao-pkg/pkg`) — no Node.js install needed on the target Windows machine. Double-click to run, then browse to `http://localhost:4200`. Built and confirmed to be a valid PE32+ Windows binary, but not execution-tested on a real Windows machine or under Wine (neither was available in the build environment) — test before relying on it.

## Security notes
- Target input is strictly validated as IPv4, IPv6, or a valid hostname/FQDN before use — arbitrary strings (including shell metacharacters) are rejected.
- All external commands run via `execFile` with argument arrays (never a shell string), so there is no command-injection surface even with malformed input.
- SSH credentials are held in memory only for the duration of a single check and are never written to disk, history, or logs.
