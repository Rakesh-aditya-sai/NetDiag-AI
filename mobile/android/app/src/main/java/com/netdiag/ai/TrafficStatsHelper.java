package com.netdiag.ai;

import android.app.AppOpsManager;
import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.TrafficStats;
import android.os.Build;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

class TrafficStatsHelper {

    static boolean hasUsageAccess(Context ctx) {
        try {
            AppOpsManager appOps = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            int mode = appOps.checkOpNoThrow(
                "android:get_usage_stats", Process.myUid(), ctx.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    static JSONObject deviceTotalsSinceBoot() {
        JSONObject o = new JSONObject();
        try {
            o.put("totalRxBytes", TrafficStats.getTotalRxBytes());
            o.put("totalTxBytes", TrafficStats.getTotalTxBytes());
            o.put("mobileRxBytes", TrafficStats.getMobileRxBytes());
            o.put("mobileTxBytes", TrafficStats.getMobileTxBytes());
        } catch (Exception ignored) {}
        return o;
    }

    private static class Usage {
        long rx;
        long tx;
    }

    private static void accumulate(Map<Integer, Usage> byUid, NetworkStats stats) {
        if (stats == null) return;
        NetworkStats.Bucket bucket = new NetworkStats.Bucket();
        while (stats.hasNextBucket()) {
            stats.getNextBucket(bucket);
            Usage u = byUid.computeIfAbsent(bucket.getUid(), k -> new Usage());
            u.rx += bucket.getRxBytes();
            u.tx += bucket.getTxBytes();
        }
        stats.close();
    }

    /** Queries device-wide + per-app usage for [startMs, endMs). Wi-Fi is always attempted;
     * mobile is best-effort since subscriberId access varies by OEM/Android version. */
    static JSONObject queryUsage(Context ctx, long startMs, long endMs) {
        JSONObject result = new JSONObject();
        boolean wifiOk = false;
        boolean mobileOk = false;
        Map<Integer, Usage> byUid = new HashMap<>();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && hasUsageAccess(ctx)) {
            NetworkStatsManager nsm = (NetworkStatsManager) ctx.getSystemService(Context.NETWORK_STATS_SERVICE);
            try {
                NetworkStats wifi = nsm.querySummary(ConnectivityManager.TYPE_WIFI, null, startMs, endMs);
                accumulate(byUid, wifi);
                wifiOk = true;
            } catch (Exception ignored) {}
            try {
                NetworkStats mobile = nsm.querySummary(ConnectivityManager.TYPE_MOBILE, null, startMs, endMs);
                accumulate(byUid, mobile);
                mobileOk = true;
            } catch (Exception ignored) {
                // subscriberId/permission quirks on some OEMs — Wi-Fi figures still stand
            }
        }

        long totalRx = 0, totalTx = 0;
        JSONArray apps = new JSONArray();
        PackageManager pm = ctx.getPackageManager();
        try {
            for (Map.Entry<Integer, Usage> e : byUid.entrySet()) {
                int uid = e.getKey();
                Usage u = e.getValue();
                totalRx += u.rx;
                totalTx += u.tx;
                if (u.rx + u.tx <= 0) continue;
                JSONObject app = new JSONObject();
                app.put("uid", uid);
                app.put("label", appLabelForUid(pm, uid));
                app.put("rxBytes", u.rx);
                app.put("txBytes", u.tx);
                apps.put(app);
            }
        } catch (Exception ignored) {}

        try {
            result.put("hasUsageAccess", hasUsageAccess(ctx));
            result.put("wifiAvailable", wifiOk);
            result.put("mobileAvailable", mobileOk);
            result.put("totalRxBytes", totalRx);
            result.put("totalTxBytes", totalTx);
            result.put("apps", apps);
        } catch (Exception ignored) {}
        return result;
    }

    private static String appLabelForUid(PackageManager pm, int uid) {
        try {
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null && pkgs.length > 0) {
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(pkgs[0], 0);
                    return pm.getApplicationLabel(ai).toString();
                } catch (Exception e) {
                    return pkgs[0];
                }
            }
        } catch (Exception ignored) {}
        if (uid == Process.SYSTEM_UID) return "Android System";
        return "uid " + uid;
    }
}
