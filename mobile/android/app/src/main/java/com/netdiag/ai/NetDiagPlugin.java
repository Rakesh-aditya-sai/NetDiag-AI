package com.netdiag.ai;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.util.Base64;

import androidx.core.content.FileProvider;

import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

@CapacitorPlugin(
    name = "NetDiag",
    permissions = {
        @Permission(alias = "notifications", strings = { Manifest.permission.POST_NOTIFICATIONS })
    }
)
public class NetDiagPlugin extends Plugin {

    private static final String MONITOR_WORK_NAME = "netdiag_monitor_work";

    private static final int[] COMMON_PORTS = {80, 443, 22, 3389, 53, 3306};
    private static final Pattern IPV4 = Pattern.compile(
        "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern HOSTNAME = Pattern.compile(
        "^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$");

    private boolean isValidTarget(String target) {
        if (target == null || target.isEmpty() || target.length() > 253) return false;
        if (target.startsWith("-")) return false;
        if (IPV4.matcher(target).matches()) return true;
        if (target.contains(":")) return true; // best-effort IPv6 accept, InetAddress validates further
        return HOSTNAME.matcher(target).matches();
    }

    private boolean isIpLiteral(String target) {
        return IPV4.matcher(target).matches() || target.contains(":");
    }

    private String fmtAddr(String ip, Integer port) {
        if (ip == null) ip = "?";
        String host = ip.contains(":") ? "[" + ip + "]" : ip;
        return port != null ? host + ":" + port : host;
    }

    private void runAsync(PluginCall call, java.util.concurrent.Callable<JSObject> task) {
        new Thread(() -> {
            try {
                call.resolve(task.call());
            } catch (Exception e) {
                JSObject ret = new JSObject();
                ret.put("status", "FAIL");
                ret.put("detail", "Unexpected error: " + e.getMessage());
                call.resolve(ret);
            }
        }).start();
    }

    private String readAll(java.io.InputStream in) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private String getLocalAddressFor(String target) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName(target), 53);
            return socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    private List<String> getDnsServers() {
        List<String> servers = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm.getActiveNetwork();
            if (active != null) {
                LinkProperties lp = cm.getLinkProperties(active);
                if (lp != null) {
                    for (InetAddress addr : lp.getDnsServers()) {
                        servers.add(addr.getHostAddress());
                    }
                }
            }
        } catch (Exception ignored) {}
        return servers;
    }

    @PluginMethod
    public void ping(PluginCall call) {
        String target = call.getString("target");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            try {
                String localAddr = getLocalAddressFor(target);
                PingStats stats = PingStats.run(target, 4, 15);
                if (!stats.ran) {
                    ret.put("status", "FAIL");
                    ret.put("detail", "Ping failed to run.");
                    return ret;
                }

                ret.put("packetLossPct", stats.packetLossPct);
                if (stats.avgLatencyMs != null) {
                    ret.put("minLatencyMs", stats.minLatencyMs);
                    ret.put("avgLatencyMs", stats.avgLatencyMs);
                    ret.put("maxLatencyMs", stats.maxLatencyMs);
                    // mdev (mean deviation of RTT samples) is the standard proxy for jitter
                    ret.put("jitterMs", stats.jitterMs);
                }

                String status = stats.packetLossPct == 0 ? "PASS" : (stats.packetLossPct < 100 ? "WARNING" : "FAIL");
                String addrLine = localAddr != null
                    ? "Source: " + localAddr + "  →  Destination: " + target + "\n" : "";
                ret.put("status", status);
                ret.put("detail", addrLine + (stats.output.trim().isEmpty() ? "No response" : stats.output.trim()));
            } catch (Exception e) {
                ret.put("status", "FAIL");
                ret.put("detail", "Ping failed: " + e.getMessage());
            }
            return ret;
        });
    }

    @PluginMethod
    public void dns(PluginCall call) {
        String target = call.getString("target");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            List<String> resolvers = getDnsServers();
            String resolverLine = "DNS server(s) queried: " + (resolvers.isEmpty() ? "unknown" : String.join(", ", resolvers));
            long start = System.nanoTime();
            try {
                if (isIpLiteral(target)) {
                    InetAddress addr = InetAddress.getByName(target);
                    ret.put("dnsResponseMs", (System.nanoTime() - start) / 1_000_000.0);
                    ret.put("resolvedIp", addr.getHostAddress());
                    String canonical = addr.getCanonicalHostName();
                    if (canonical.equals(addr.getHostAddress())) {
                        ret.put("status", "WARNING");
                        ret.put("detail", resolverLine + "\nTarget is an IP with no reverse DNS (PTR) record — this is often normal.");
                    } else {
                        ret.put("status", "PASS");
                        ret.put("detail", resolverLine + "\nReverse DNS: " + target + " → " + canonical);
                    }
                } else {
                    InetAddress[] addrs = InetAddress.getAllByName(target);
                    ret.put("dnsResponseMs", (System.nanoTime() - start) / 1_000_000.0);
                    if (addrs.length > 0) ret.put("resolvedIp", addrs[0].getHostAddress());
                    StringBuilder sb = new StringBuilder();
                    for (InetAddress a : addrs) {
                        if (sb.length() > 0) sb.append(", ");
                        sb.append(a.getHostAddress());
                    }
                    ret.put("status", "PASS");
                    ret.put("detail", resolverLine + "\n" + target + " resolved to: " + sb);
                }
            } catch (Exception e) {
                ret.put("status", "FAIL");
                ret.put("detail", resolverLine + "\nCould not resolve hostname: " + e.getMessage());
            }
            return ret;
        });
    }

    private static class PortResult {
        int port; boolean open;
        String localAddress; int localPort;
        String remoteAddress; int remotePort;
    }

    private PortResult checkPort(String target, int port, int timeoutMs) {
        PortResult r = new PortResult();
        r.port = port;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, port), timeoutMs);
            r.open = true;
            r.localAddress = socket.getLocalAddress().getHostAddress();
            r.localPort = socket.getLocalPort();
            r.remoteAddress = ((InetSocketAddress) socket.getRemoteSocketAddress()).getAddress().getHostAddress();
            r.remotePort = port;
        } catch (Exception e) {
            r.open = false;
        }
        return r;
    }

    private List<Integer> parseCustomPorts(String customPorts) {
        List<Integer> ports = new ArrayList<>();
        if (customPorts == null || customPorts.trim().isEmpty()) return ports;
        for (String p : customPorts.split(",")) {
            try {
                int n = Integer.parseInt(p.trim());
                if (n >= 1 && n <= 65535) ports.add(n);
            } catch (NumberFormatException ignored) {}
        }
        return ports;
    }

    @PluginMethod
    public void firewall(PluginCall call) {
        String target = call.getString("target");
        String customPorts = call.getString("customPorts");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            Set<Integer> portSet = new LinkedHashSet<>();
            for (int p : COMMON_PORTS) portSet.add(p);
            portSet.addAll(parseCustomPorts(customPorts));

            ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, portSet.size()));
            List<Future<PortResult>> futures = new ArrayList<>();
            for (int port : portSet) {
                futures.add(pool.submit(() -> checkPort(target, port, 2000)));
            }
            List<PortResult> results = new ArrayList<>();
            for (Future<PortResult> f : futures) {
                try { results.add(f.get(4, TimeUnit.SECONDS)); } catch (Exception ignored) {}
            }
            pool.shutdownNow();

            List<Integer> open = new ArrayList<>();
            List<Integer> closed = new ArrayList<>();
            StringBuilder lines = new StringBuilder();
            for (PortResult r : results) {
                if (r.open) {
                    open.add(r.port);
                    lines.append("Port ").append(r.port).append(": OPEN     src ")
                        .append(fmtAddr(r.localAddress, r.localPort)).append("  →  dst ")
                        .append(fmtAddr(r.remoteAddress, r.remotePort)).append('\n');
                } else {
                    closed.add(r.port);
                    lines.append("Port ").append(r.port).append(": CLOSED/FILTERED  →  dst ")
                        .append(fmtAddr(target, r.port)).append('\n');
                }
            }
            ret.put("status", open.isEmpty() ? "WARNING" : "PASS");
            ret.put("detail", "Open: " + open + "  Closed/Filtered: " + closed + "\n\n" + lines.toString().trim());
            org.json.JSONArray openArr = new org.json.JSONArray();
            for (int p : open) openArr.put(p);
            org.json.JSONArray closedArr = new org.json.JSONArray();
            for (int p : closed) closedArr.put(p);
            ret.put("openPorts", openArr);
            ret.put("closedPorts", closedArr);
            return ret;
        });
    }

    @PluginMethod
    public void traceroute(PluginCall call) {
        String target = call.getString("target");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            String localAddr = getLocalAddressFor(target);
            StringBuilder sb = new StringBuilder();
            if (localAddr != null) {
                sb.append("Source: ").append(localAddr).append("  →  Destination: ").append(target).append('\n');
            }
            boolean reached = false;
            int hopCount = 0;
            try {
                for (int ttl = 1; ttl <= 12; ttl++) {
                    Process p = new ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "2", "-t", String.valueOf(ttl), target)
                        .redirectErrorStream(true).start();
                    String output = readAll(p.getInputStream());
                    p.waitFor(4, TimeUnit.SECONDS);

                    String hopLine = "hop " + ttl + ": ";
                    if (output.toLowerCase().contains("time to live exceeded")) {
                        Matcher m = Pattern.compile("From ([0-9a-fA-F.:]+)").matcher(output);
                        hopLine += m.find() ? m.group(1) + " (TTL exceeded)" : "intermediate hop (TTL exceeded)";
                        hopCount++;
                    } else if (output.contains("1 received") || output.contains("1 packets received")) {
                        hopLine += target + " (reached)";
                        sb.append(hopLine).append('\n');
                        reached = true;
                        hopCount++;
                        break;
                    } else {
                        hopLine += "no reply";
                        hopCount++;
                    }
                    sb.append(hopLine).append('\n');
                }
            } catch (Exception e) {
                ret.put("status", "FAIL");
                ret.put("detail", "Traceroute failed: " + e.getMessage());
                return ret;
            }
            ret.put("status", reached ? "PASS" : "WARNING");
            ret.put("detail", sb.length() > 0 ? sb.toString().trim() : "No trace data (device ping may not support -t TTL option)");
            ret.put("hopCount", hopCount);
            return ret;
        });
    }

    private static SSLSocketFactory permissiveSslFactory() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAll, new SecureRandom());
        return sc.getSocketFactory();
    }

    private JSObject httpProbe(String target, int port, boolean tls) {
        JSObject r = new JSObject();
        Socket rawSocket = null;
        Socket ioSocket = null;
        try {
            rawSocket = new Socket();
            rawSocket.connect(new InetSocketAddress(target, port), 4000);
            String localAddr = rawSocket.getLocalAddress().getHostAddress();
            int localPort = rawSocket.getLocalPort();
            String remoteAddr = ((InetSocketAddress) rawSocket.getRemoteSocketAddress()).getAddress().getHostAddress();

            if (tls) {
                SSLSocket sslSocket = (SSLSocket) permissiveSslFactory().createSocket(rawSocket, target, port, true);
                sslSocket.setSoTimeout(4000);
                sslSocket.startHandshake();
                ioSocket = sslSocket;
            } else {
                rawSocket.setSoTimeout(4000);
                ioSocket = rawSocket;
            }

            OutputStream out = ioSocket.getOutputStream();
            String req = "HEAD / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n";
            out.write(req.getBytes("UTF-8"));
            out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(ioSocket.getInputStream()));
            String statusLine = reader.readLine();
            int code = 0;
            if (statusLine != null) {
                String[] parts = statusLine.split(" ");
                if (parts.length >= 2) {
                    try { code = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
                }
            }

            r.put("ok", true);
            r.put("code", code);
            r.put("localAddress", localAddr);
            r.put("localPort", localPort);
            r.put("remoteAddress", remoteAddr);
            r.put("remotePort", port);
        } catch (Exception e) {
            r.put("ok", false);
            r.put("error", e.getMessage());
        } finally {
            try { if (ioSocket != null) ioSocket.close(); else if (rawSocket != null) rawSocket.close(); } catch (Exception ignored) {}
        }
        return r;
    }

    @PluginMethod
    public void cloud(PluginCall call) {
        String target = call.getString("target");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            JSObject https = httpProbe(target, 443, true);
            if (https.getBoolean("ok", false)) {
                ret.put("status", "PASS");
                ret.put("detail", "HTTPS reachable, status " + https.getInteger("code") + "\nsrc "
                    + fmtAddr(https.getString("localAddress"), https.getInteger("localPort")) + "  →  dst "
                    + fmtAddr(https.getString("remoteAddress"), https.getInteger("remotePort")));
                return ret;
            }
            JSObject http = httpProbe(target, 80, false);
            if (http.getBoolean("ok", false)) {
                ret.put("status", "WARNING");
                ret.put("detail", "HTTPS failed (" + https.getString("error") + "); HTTP reachable, status " + http.getInteger("code") + "\nsrc "
                    + fmtAddr(http.getString("localAddress"), http.getInteger("localPort")) + "  →  dst "
                    + fmtAddr(http.getString("remoteAddress"), http.getInteger("remotePort")));
                return ret;
            }
            ret.put("status", "FAIL");
            ret.put("detail", "HTTPS failed (" + https.getString("error") + "); HTTP failed (" + http.getString("error") + ")");
            return ret;
        });
    }

    @PluginMethod
    public void shareFile(PluginCall call) {
        String filename = call.getString("filename", "netdiag-file.dat");
        String base64 = call.getString("base64");
        String mimeType = call.getString("mimeType", "application/octet-stream");
        if (base64 == null) {
            call.reject("Missing file data.");
            return;
        }
        try {
            java.io.File dir = new java.io.File(getContext().getCacheDir(), "shared");
            if (!dir.exists()) dir.mkdirs();
            java.io.File file = new java.io.File(dir, filename);
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
                out.write(Base64.decode(base64, Base64.DEFAULT));
            }
            Uri uri = FileProvider.getUriForFile(getContext(), getContext().getPackageName() + ".fileprovider", file);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType(mimeType);
            shareIntent.putExtra(Intent.EXTRA_STREAM, uri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            Intent chooser = Intent.createChooser(shareIntent, "Share NetDiag AI file");
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            getContext().startActivity(chooser);
            call.resolve();
        } catch (Exception e) {
            call.reject("Could not share file: " + e.getMessage());
        }
    }

    @PluginMethod
    public void sslInfo(PluginCall call) {
        String target = call.getString("target");
        Integer portArg = call.getInt("port");
        int port = portArg != null ? portArg : 443;
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            if (!isValidTarget(target)) {
                ret.put("status", "FAIL");
                ret.put("detail", "Invalid target.");
                return ret;
            }
            Socket rawSocket = null;
            SSLSocket sslSocket = null;
            try {
                rawSocket = new Socket();
                rawSocket.connect(new InetSocketAddress(target, port), 5000);
                sslSocket = (SSLSocket) permissiveSslFactory().createSocket(rawSocket, target, port, true);
                sslSocket.setSoTimeout(5000);
                sslSocket.startHandshake();

                X509Certificate[] chain = (X509Certificate[]) sslSocket.getSession().getPeerCertificates();
                X509Certificate cert = chain[0];
                java.util.Date now = new java.util.Date();
                long daysLeft = (cert.getNotAfter().getTime() - now.getTime()) / (1000L * 60 * 60 * 24);

                StringBuilder sb = new StringBuilder();
                sb.append("Subject: ").append(cert.getSubjectDN()).append('\n');
                sb.append("Issuer: ").append(cert.getIssuerDN()).append('\n');
                sb.append("Valid from: ").append(cert.getNotBefore()).append('\n');
                sb.append("Valid until: ").append(cert.getNotAfter()).append('\n');
                sb.append("Days until expiry: ").append(daysLeft).append('\n');
                sb.append("Chain length: ").append(chain.length).append('\n');
                sb.append("Protocol: ").append(sslSocket.getSession().getProtocol()).append('\n');
                sb.append("Cipher suite: ").append(sslSocket.getSession().getCipherSuite());

                ret.put("daysUntilExpiry", daysLeft);
                if (daysLeft < 0) {
                    ret.put("status", "FAIL");
                    sb.insert(0, "Certificate has EXPIRED.\n\n");
                } else if (daysLeft < 14) {
                    ret.put("status", "WARNING");
                    sb.insert(0, "Certificate expires soon.\n\n");
                } else {
                    ret.put("status", "PASS");
                }
                ret.put("detail", sb.toString());
            } catch (Exception e) {
                ret.put("status", "FAIL");
                ret.put("detail", "Could not retrieve certificate: " + e.getMessage());
            } finally {
                try { if (sslSocket != null) sslSocket.close(); else if (rawSocket != null) rawSocket.close(); } catch (Exception ignored) {}
            }
            return ret;
        });
    }

    // --- Device / network context (for enterprise-style reporting) ---

    @PluginMethod
    public void getDeviceContext(PluginCall call) {
        JSObject ret = new JSObject();
        try {
            ConnectivityManager cm = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm.getActiveNetwork();
            android.net.NetworkCapabilities caps = active != null ? cm.getNetworkCapabilities(active) : null;
            String connectionType = "Unknown";
            boolean vpnActive = false;
            if (caps != null) {
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) connectionType = "Wi-Fi";
                else if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) connectionType = "Mobile Data";
                else if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) connectionType = "Ethernet";
                vpnActive = caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN);
            }
            ret.put("connectionType", connectionType);
            ret.put("vpnActive", vpnActive);

            String localIp = null, gatewayIp = null;
            if (active != null) {
                LinkProperties lp = cm.getLinkProperties(active);
                if (lp != null) {
                    for (android.net.LinkAddress la : lp.getLinkAddresses()) {
                        if (la.getAddress() instanceof java.net.Inet4Address) {
                            localIp = la.getAddress().getHostAddress();
                            break;
                        }
                    }
                    for (android.net.RouteInfo route : lp.getRoutes()) {
                        if (route.isDefaultRoute() && route.getGateway() instanceof java.net.Inet4Address) {
                            gatewayIp = route.getGateway().getHostAddress();
                            break;
                        }
                    }
                    if (gatewayIp == null) {
                        for (android.net.RouteInfo route : lp.getRoutes()) {
                            if (route.isDefaultRoute() && route.getGateway() != null) {
                                gatewayIp = route.getGateway().getHostAddress();
                                break;
                            }
                        }
                    }
                }
            }
            ret.put("localIp", localIp);
            ret.put("gatewayIp", gatewayIp);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                String privateDnsMode = Settings.Global.getString(getContext().getContentResolver(), "private_dns_mode");
                ret.put("privateDnsMode", privateDnsMode != null ? privateDnsMode : "off");
            }

            ret.put("deviceModel", Build.MANUFACTURER + " " + Build.MODEL);
            ret.put("androidVersion", Build.VERSION.RELEASE);
            try {
                String versionName = getContext().getPackageManager()
                    .getPackageInfo(getContext().getPackageName(), 0).versionName;
                ret.put("appVersion", versionName);
            } catch (Exception ignored) {}
        } catch (Exception e) {
            ret.put("error", e.getMessage());
        }
        call.resolve(ret);
    }

    // --- Device traffic monitor ---

    @PluginMethod
    public void getTrafficSnapshot(PluginCall call) {
        JSObject ret = new JSObject();
        JSONObject totals = TrafficStatsHelper.deviceTotalsSinceBoot();
        java.util.Iterator<String> keys = totals.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            try { ret.put(k, totals.get(k)); } catch (Exception ignored) {}
        }
        call.resolve(ret);
    }

    @PluginMethod
    public void hasUsageAccess(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("granted", TrafficStatsHelper.hasUsageAccess(getContext()));
        call.resolve(ret);
    }

    @PluginMethod
    public void openUsageAccessSettings(PluginCall call) {
        try {
            Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            getContext().startActivity(intent);
            call.resolve();
        } catch (Exception e) {
            call.reject("Could not open settings: " + e.getMessage());
        }
    }

    @PluginMethod
    public void getUsageSummary(PluginCall call) {
        Long startMs = call.getLong("startMs");
        Long endMs = call.getLong("endMs");
        if (startMs == null || endMs == null) {
            call.reject("startMs and endMs are required.");
            return;
        }
        runAsync(call, () -> {
            JSONObject summary = TrafficStatsHelper.queryUsage(getContext(), startMs, endMs);
            JSObject ret = new JSObject();
            java.util.Iterator<String> keys = summary.keys();
            while (keys.hasNext()) {
                String k = keys.next();
                try { ret.put(k, summary.get(k)); } catch (Exception ignored) {}
            }
            return ret;
        });
    }

    // --- Terminal (sandboxed, allow-listed network commands) ---

    @PluginMethod
    public void runTerminalCommand(PluginCall call) {
        String input = call.getString("input", "");
        runAsync(call, () -> {
            JSObject ret = new JSObject();
            ret.put("output", TerminalCommands.run(getContext(), input));
            return ret;
        });
    }

    // --- Background monitoring / alerts ---

    @PluginMethod
    public void getWatchedTargets(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("targets", MonitorStore.getWatchedTargets(getContext()));
        call.resolve(ret);
    }

    @PluginMethod
    public void setWatchedTargets(PluginCall call) {
        JSArray targets = call.getArray("targets");
        MonitorStore.setWatchedTargets(getContext(), targets != null ? targets : new JSONArray());
        call.resolve();
    }

    @PluginMethod
    public void getMonitoringEnabled(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("enabled", MonitorStore.isMonitoringEnabled(getContext()));
        call.resolve(ret);
    }

    @PluginMethod
    public void setMonitoringEnabled(PluginCall call) {
        boolean enabled = Boolean.TRUE.equals(call.getBoolean("enabled"));
        MonitorStore.setMonitoringEnabled(getContext(), enabled);
        WorkManager wm = WorkManager.getInstance(getContext());
        if (enabled) {
            PeriodicWorkRequest work = new PeriodicWorkRequest.Builder(
                MonitorWorker.class, 15, TimeUnit.MINUTES).build();
            wm.enqueueUniquePeriodicWork(MONITOR_WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, work);
        } else {
            wm.cancelUniqueWork(MONITOR_WORK_NAME);
        }
        call.resolve();
    }

    @PluginMethod
    public void drainBackgroundResults(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("results", MonitorStore.drainPendingResults(getContext()));
        call.resolve(ret);
    }

    @PluginMethod
    public void ensureNotificationPermission(PluginCall call) {
        if (getPermissionState("notifications") == PermissionState.GRANTED) {
            JSObject ret = new JSObject();
            ret.put("granted", true);
            call.resolve(ret);
            return;
        }
        requestPermissionForAlias("notifications", call, "notificationPermCallback");
    }

    @PermissionCallback
    private void notificationPermCallback(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("granted", getPermissionState("notifications") == PermissionState.GRANTED);
        call.resolve(ret);
    }
}
