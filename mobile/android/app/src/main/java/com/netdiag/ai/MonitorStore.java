package com.netdiag.ai;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

class MonitorStore {
    private static final String PREFS = "netdiag_monitor";
    private static final String KEY_TARGETS = "watched_targets";
    private static final String KEY_PENDING = "pending_results";
    private static final String KEY_ENABLED = "monitoring_enabled";
    private static final int MAX_PENDING = 200;

    static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static JSONArray getWatchedTargets(Context ctx) {
        try {
            return new JSONArray(prefs(ctx).getString(KEY_TARGETS, "[]"));
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    static void setWatchedTargets(Context ctx, JSONArray targets) {
        prefs(ctx).edit().putString(KEY_TARGETS, targets.toString()).apply();
    }

    static boolean isMonitoringEnabled(Context ctx) {
        return prefs(ctx).getBoolean(KEY_ENABLED, false);
    }

    static void setMonitoringEnabled(Context ctx, boolean enabled) {
        prefs(ctx).edit().putBoolean(KEY_ENABLED, enabled).apply();
    }

    static synchronized void appendPendingResult(Context ctx, JSONObject result) {
        try {
            JSONArray pending = new JSONArray(prefs(ctx).getString(KEY_PENDING, "[]"));
            pending.put(result);
            // trim from the front if over cap
            while (pending.length() > MAX_PENDING) {
                JSONArray trimmed = new JSONArray();
                for (int i = 1; i < pending.length(); i++) trimmed.put(pending.get(i));
                pending = trimmed;
            }
            prefs(ctx).edit().putString(KEY_PENDING, pending.toString()).apply();
        } catch (Exception ignored) {}
    }

    static synchronized JSONArray drainPendingResults(Context ctx) {
        JSONArray pending;
        try {
            pending = new JSONArray(prefs(ctx).getString(KEY_PENDING, "[]"));
        } catch (Exception e) {
            pending = new JSONArray();
        }
        prefs(ctx).edit().putString(KEY_PENDING, "[]").apply();
        return pending;
    }
}
