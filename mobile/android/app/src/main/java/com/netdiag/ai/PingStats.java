package com.netdiag.ai;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class PingStats {
    private static final Pattern PACKET_LOSS = Pattern.compile("(\\d+)% packet loss");
    private static final Pattern RTT_STATS = Pattern.compile(
        "rtt min/avg/max/(?:mdev|stddev) = ([\\d.]+)/([\\d.]+)/([\\d.]+)/([\\d.]+)");

    final boolean ran;
    final String output;
    final double packetLossPct;
    final Double avgLatencyMs;
    final Double minLatencyMs;
    final Double maxLatencyMs;
    final Double jitterMs;

    private PingStats(boolean ran, String output, double packetLossPct, Double avg, Double min, Double max, Double jitter) {
        this.ran = ran;
        this.output = output;
        this.packetLossPct = packetLossPct;
        this.avgLatencyMs = avg;
        this.minLatencyMs = min;
        this.maxLatencyMs = max;
        this.jitterMs = jitter;
    }

    static PingStats run(String target, int count, int timeoutSec) {
        try {
            Process p = new ProcessBuilder("/system/bin/ping", "-c", String.valueOf(count), "-W", "2", target)
                .redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) sb.append(line).append('\n');
            p.waitFor(timeoutSec, TimeUnit.SECONDS);
            String output = sb.toString();

            Matcher m = PACKET_LOSS.matcher(output);
            double loss = 100;
            if (m.find()) loss = Integer.parseInt(m.group(1));

            Double avg = null, min = null, max = null, jitter = null;
            Matcher rtt = RTT_STATS.matcher(output);
            if (rtt.find()) {
                min = Double.parseDouble(rtt.group(1));
                avg = Double.parseDouble(rtt.group(2));
                max = Double.parseDouble(rtt.group(3));
                jitter = Double.parseDouble(rtt.group(4));
            }
            return new PingStats(true, output, loss, avg, min, max, jitter);
        } catch (Exception e) {
            return new PingStats(false, "", 100, null, null, null, null);
        }
    }
}
