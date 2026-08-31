# NetDiag AI — Network Troubleshooting Assistant

A small web app for support engineers: enter a device's IP or FQDN, pick which checks to run, and get PASS/WARNING/FAIL results plus suggested next steps. Generates a downloadable TAC-ready text report.

## Checks
- Connectivity (ping)
- DNS resolution (forward + reverse)
- Firewall / common port check (80, 443, 22, 3389, 53, 3306)
- Traceroute (IPv4, capped at 15 hops / 10s)
- Cloud / HTTP(S) reachability

## Run

```
cd /home/raki/NetDiagAI
npm start
```

Opens on `http://localhost:4200`. To use from your phone or another device on the same WiFi, allow the port through the firewall once:

```
sudo ufw allow 4200/tcp
```

then browse to `http://<this-PC's-LAN-IP>:4200` (find it with `hostname -I`).

## Security notes
- Target input is strictly validated as IPv4, IPv6, or a valid hostname/FQDN before use — arbitrary strings (including shell metacharacters) are rejected.
- All external commands run via `execFile` with argument arrays (never a shell string), so there is no command-injection surface even with malformed input.
