package com.netdiag.ai;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

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

@CapacitorPlugin(name = "NetDiag")
public class NetDiagPlugin extends Plugin {

    private static final int[] COMMON_PORTS = {80, 443, 22, 3389, 53, 3306};
    private static final Pattern IPV4 = Pattern.compile(
        "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern HOSTNAME = Pattern.compile(
        "^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$");
    private static final Pattern PACKET_LOSS = Pattern.compile("(\\d+)% packet loss");

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
                Process p = new ProcessBuilder("/system/bin/ping", "-c", "4", "-W", "2", target)
                    .redirectErrorStream(true).start();
                String output = readAll(p.getInputStream());
                p.waitFor(15, TimeUnit.SECONDS);

                Matcher m = PACKET_LOSS.matcher(output);
                int loss = 100;
                if (m.find()) loss = Integer.parseInt(m.group(1));

                String status = loss == 0 ? "PASS" : (loss < 100 ? "WARNING" : "FAIL");
                String addrLine = localAddr != null
                    ? "Source: " + localAddr + "  →  Destination: " + target + "\n" : "";
                ret.put("status", status);
                ret.put("detail", addrLine + (output.trim().isEmpty() ? "No response" : output.trim()));
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
            try {
                if (isIpLiteral(target)) {
                    InetAddress addr = InetAddress.getByName(target);
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
                    } else if (output.contains("1 received") || output.contains("1 packets received")) {
                        hopLine += target + " (reached)";
                        sb.append(hopLine).append('\n');
                        reached = true;
                        break;
                    } else {
                        hopLine += "no reply";
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
}
