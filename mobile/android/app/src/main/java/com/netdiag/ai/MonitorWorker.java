package com.netdiag.ai;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import org.json.JSONArray;
import org.json.JSONObject;

public class MonitorWorker extends Worker {

    public MonitorWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context ctx = getApplicationContext();
        if (!MonitorStore.isMonitoringEnabled(ctx)) return Result.success();

        JSONArray targets = MonitorStore.getWatchedTargets(ctx);
        for (int i = 0; i < targets.length(); i++) {
            try {
                JSONObject t = targets.getJSONObject(i);
                if (!t.optBoolean("enabled", true)) continue;
                checkTarget(ctx, t);
            } catch (Exception ignored) {}
        }
        return Result.success();
    }

    private void checkTarget(Context ctx, JSONObject t) throws Exception {
        String target = t.getString("target");
        double latencyThreshold = t.optDouble("latencyThresholdMs", 300);
        double lossThreshold = t.optDouble("lossThresholdPct", 20);

        PingStats stats = PingStats.run(target, 4, 10);

        boolean breached = !stats.ran
            || stats.packetLossPct >= lossThreshold
            || (stats.avgLatencyMs != null && stats.avgLatencyMs > latencyThreshold);

        JSONObject result = new JSONObject();
        result.put("target", target);
        result.put("timestamp", System.currentTimeMillis());
        result.put("packetLossPct", stats.packetLossPct);
        if (stats.avgLatencyMs != null) {
            result.put("avgLatencyMs", stats.avgLatencyMs);
            result.put("minLatencyMs", stats.minLatencyMs);
            result.put("maxLatencyMs", stats.maxLatencyMs);
            result.put("jitterMs", stats.jitterMs);
        }
        result.put("breached", breached);
        MonitorStore.appendPendingResult(ctx, result);

        if (breached) notifyBreach(ctx, target, stats, latencyThreshold, lossThreshold);
    }

    private void notifyBreach(Context ctx, String target, PingStats stats, double latencyThreshold, double lossThreshold) {
        if (Build.VERSION.SDK_INT >= 33
            && ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        NotificationHelper.ensureChannel(ctx);

        String reason;
        if (!stats.ran || stats.packetLossPct >= 100) {
            reason = target + " is unreachable.";
        } else if (stats.packetLossPct >= lossThreshold) {
            reason = target + ": packet loss " + (int) stats.packetLossPct + "% (threshold " + (int) lossThreshold + "%).";
        } else {
            reason = target + ": latency " + String.format("%.0f", stats.avgLatencyMs) + " ms (threshold " + (int) latencyThreshold + " ms).";
        }

        Intent openApp = new Intent(ctx, MainActivity.class);
        openApp.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(ctx, target.hashCode(), openApp, flags);

        Notification notification = new NotificationCompat.Builder(ctx, NotificationHelper.CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("NetDiag AI — network issue detected")
            .setContentText(reason)
            .setStyle(new NotificationCompat.BigTextStyle().bigText(reason))
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build();

        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        nm.notify(target.hashCode(), notification);
    }
}
