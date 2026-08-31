# NetDiag AI — Mobile (Android)

Standalone Android port of NetDiag AI. Every diagnostic runs natively on-device via a custom Capacitor plugin (`android/app/src/main/java/com/netdiag/ai/NetDiagPlugin.java`) — no PC, server, or shared-network requirement.

## Checks
- Connectivity (ping): shells out to `/system/bin/ping`
- DNS Resolution: `java.net.InetAddress`, plus the actual DNS server(s) the device is configured to use (via `ConnectivityManager`)
- Firewall / Port Check: `java.net.Socket`, default common ports plus any custom ports you enter, parallelized
- Traceroute (best-effort): loops `ping -c 1 -t <ttl>` to walk hops via TTL-exceeded ICMP replies
- Cloud / HTTP(S) Reachability: raw socket + manual HTTP HEAD request (so the real source/destination socket endpoint is visible)

Every check result shows the actual source and destination IP:port used.

## Build

```
cd mobile
npm install
npx cap copy android
cd android
./gradlew assembleDebug
```

APK output: `android/app/build/outputs/apk/debug/app-debug.apk`. Install with `adb install -r <path>`.

## Package
`com.netdiag.ai`
