# NetDiag AI — Network Troubleshooting Assistant

A network diagnostics tool for support/network engineers: enter a device's IP or FQDN, run connectivity/DNS/firewall/traceroute/HTTP checks, and get PASS/WARNING/FAIL results with suggested next steps and full source/destination IP:port detail for every check.

Two implementations of the same idea, in this repo:

- **[`web/`](web/)** — Node.js/Express web app. Runs on a PC/server, backend shells out to real system tools (ping, tracepath) and Node's net/dns/http modules. Accessible from any device on the same network.
- **[`mobile/`](mobile/)** — Standalone Android app (Capacitor + a custom native Kotlin/Java plugin). All diagnostics run 100% on-device — no server, no network dependency beyond what you're actually testing.

## Features

- Connectivity (ping), DNS resolution (with the resolver server used), firewall/port scanning (including custom ports), traceroute, and HTTP(S) reachability
- Every result shows real source and destination IP:port, not just pass/fail
- Rule-based root-cause suggestions (e.g. "resolves fine but no ICMP reply → likely firewall blocking, not an outage") — no external AI API dependency
- Downloadable/shareable TAC-ready report
- Strict input validation (IPv4/IPv6/FQDN only) — no command-injection surface even though real system commands are invoked

## Origin

Idea originated from a casual "suggest my next project" conversation, refined into a practical tool that reflects real day-to-day network/support troubleshooting workflows.
