package com.netdiag.ai;

import android.content.Context;
import android.os.Build;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * A sandboxed, allow-listed command interpreter for the Terminal tab.
 * Every command runs as a literal argv array via ProcessBuilder — never through a shell —
 * so shell metacharacters typed by the user (;, |, &&, backticks) carry no special meaning.
 * Anything not on the allow-list below is rejected outright.
 */
class TerminalCommands {

    private static final Pattern IPV4 = Pattern.compile(
        "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern HOSTNAME = Pattern.compile(
        "^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$");

    private static boolean isValidHost(String h) {
        if (h == null || h.isEmpty() || h.length() > 253) return false;
        if (IPV4.matcher(h).matches()) return true;
        if (h.contains(":")) return true;
        return HOSTNAME.matcher(h).matches();
    }

    static String run(Context ctx, String input) {
        if (input == null) return "";
        String trimmed = input.trim();
        if (trimmed.isEmpty()) return "";
        String[] tokens = trimmed.split("\\s+");
        String cmd = tokens[0].toLowerCase();
        String[] args = new String[tokens.length - 1];
        System.arraycopy(tokens, 1, args, 0, args.length);

        try {
            switch (cmd) {
                case "help": return help();
                case "ping": return ping(args);
                case "ping6": return ping6(args);
                case "traceroute":
                case "tracepath": return traceroute(args);
                case "nslookup":
                case "dig": return nslookup(args);
                case "ifconfig":
                case "ip": return ifconfig();
                case "netstat": return netstat();
                case "whoami": return "netdiag-ai (sandboxed app process, uid " + android.os.Process.myUid() + ")\nThis is not a root shell — commands run with this app's own permissions only.";
                case "hostname": return Build.MODEL;
                case "date": return new Date().toString();
                case "uptime": {
                    long upMs = SystemClock.elapsedRealtime();
                    long h = TimeUnit.MILLISECONDS.toHours(upMs);
                    long m = TimeUnit.MILLISECONDS.toMinutes(upMs) % 60;
                    return "up " + h + "h " + m + "m (device uptime)";
                }
                case "echo": return String.join(" ", args);
                case "clear": return "";
                default:
                    return "netdiag-terminal: command not found: '" + cmd + "'\nType 'help' for the list of available commands.";
            }
        } catch (Exception e) {
            return "Error running '" + cmd + "': " + e.getMessage();
        }
    }

    private static String help() {
        return "NetDiag AI Terminal — a sandboxed subset of network/troubleshooting commands.\n"
            + "This runs inside the app's own sandbox (not a root shell); a fixed allow-list of\n"
            + "commands is supported and anything else is rejected.\n\n"
            + "Available commands:\n"
            + "  ping <host> [-c N]      ICMP ping (default 4 packets, max 10)\n"
            + "  ping6 <host>            ICMP ping over IPv6 (if supported on this device)\n"
            + "  traceroute <host>       best-effort TTL-based trace\n"
            + "  tracepath <host>        alias of traceroute\n"
            + "  nslookup <host>         DNS resolution\n"
            + "  dig <host>              alias of nslookup\n"
            + "  ifconfig / ip           list network interfaces and addresses\n"
            + "  netstat                 best-effort local socket listing\n"
            + "  whoami                  show the app sandbox identity\n"
            + "  hostname                show the device model name\n"
            + "  date                    current date/time\n"
            + "  uptime                  device uptime\n"
            + "  echo <text>             print text back\n"
            + "  clear                   clear the terminal screen";
    }

    private static String requireHost(String[] args) {
        for (String a : args) {
            if (!a.startsWith("-") && isValidHost(a)) return a;
        }
        return null;
    }

    private static int extractCount(String[] args, int def, int max) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("-c")) {
                try {
                    int n = Integer.parseInt(args[i + 1]);
                    return Math.max(1, Math.min(max, n));
                } catch (NumberFormatException ignored) {}
            }
        }
        return def;
    }

    private static String ping(String[] args) throws Exception {
        String host = requireHost(args);
        if (host == null) return "usage: ping <host> [-c N]";
        int count = extractCount(args, 4, 10);
        PingStats stats = PingStats.run(host, count, 15);
        if (!stats.ran) return "ping: failed to run.";
        return stats.output.trim().isEmpty() ? "No response" : stats.output.trim();
    }

    private static String ping6(String[] args) throws Exception {
        String host = requireHost(args);
        if (host == null) return "usage: ping6 <host>";
        try {
            int count = extractCount(args, 4, 10);
            Process p = new ProcessBuilder("/system/bin/ping6", "-c", String.valueOf(count), "-W", "2", host)
                .redirectErrorStream(true).start();
            String out = readAll(p.getInputStream());
            p.waitFor(15, TimeUnit.SECONDS);
            return out.trim().isEmpty() ? "No response" : out.trim();
        } catch (Exception e) {
            return "ping6 is not available on this device.";
        }
    }

    private static String traceroute(String[] args) throws Exception {
        String host = requireHost(args);
        if (host == null) return "usage: traceroute <host>";
        StringBuilder sb = new StringBuilder();
        boolean reached = false;
        for (int ttl = 1; ttl <= 20; ttl++) {
            Process p = new ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "2", "-t", String.valueOf(ttl), host)
                .redirectErrorStream(true).start();
            String output = readAll(p.getInputStream());
            p.waitFor(4, TimeUnit.SECONDS);
            String hopLine = ttl + "  ";
            if (output.toLowerCase().contains("time to live exceeded")) {
                java.util.regex.Matcher m = Pattern.compile("From ([0-9a-fA-F.:]+)").matcher(output);
                hopLine += m.find() ? m.group(1) : "* (TTL exceeded)";
            } else if (output.contains("1 received") || output.contains("1 packets received")) {
                hopLine += host + "  (reached)";
                sb.append(hopLine).append('\n');
                reached = true;
                break;
            } else {
                hopLine += "* * *";
            }
            sb.append(hopLine).append('\n');
        }
        if (!reached) sb.append("(destination not confirmed reached within 20 hops)");
        return sb.toString().trim();
    }

    private static String nslookup(String[] args) throws Exception {
        String host = requireHost(args);
        if (host == null) return "usage: nslookup <host>";
        StringBuilder sb = new StringBuilder();
        InetAddress[] addrs = InetAddress.getAllByName(host);
        sb.append("Name:    ").append(host).append('\n');
        for (InetAddress a : addrs) {
            sb.append("Address: ").append(a.getHostAddress()).append('\n');
        }
        return sb.toString().trim();
    }

    private static String ifconfig() {
        for (String[] cmd : new String[][]{{"/system/bin/ip", "addr"}, {"/system/bin/ifconfig"}}) {
            try {
                Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
                String out = readAll(p.getInputStream());
                boolean finished = p.waitFor(5, TimeUnit.SECONDS);
                if (finished && p.exitValue() == 0 && !out.trim().isEmpty()) return out.trim();
            } catch (Exception ignored) {}
        }
        // Fallback: enumerate interfaces via Java (always available, no binary needed)
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                sb.append(ni.getName()).append(": ").append(ni.isUp() ? "UP" : "DOWN").append('\n');
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    sb.append("    inet ").append(addrs.nextElement().getHostAddress()).append('\n');
                }
            }
        } catch (Exception e) {
            return "Could not enumerate network interfaces: " + e.getMessage();
        }
        return sb.length() > 0 ? sb.toString().trim() : "No network interfaces found.";
    }

    private static String netstat() {
        try {
            Process p = new ProcessBuilder("/system/bin/netstat").redirectErrorStream(true).start();
            String out = readAll(p.getInputStream());
            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            if (finished && p.exitValue() == 0 && !out.trim().isEmpty()) return out.trim();
        } catch (Exception ignored) {}
        return "netstat is not available on this device (Android restricts access to other apps' "
            + "socket tables from Android 11 onward). Use the Diagnose tab's Firewall/Port Check instead.";
    }

    private static String readAll(java.io.InputStream in) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line).append('\n');
        return sb.toString();
    }
}
