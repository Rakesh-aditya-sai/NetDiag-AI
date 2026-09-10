package com.netdiag.ai;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

class NotificationHelper {
    static final String CHANNEL_ID = "netdiag_alerts";

    static void ensureChannel(Context ctx) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = ctx.getSystemService(NotificationManager.class);
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Network Alerts", NotificationManager.IMPORTANCE_DEFAULT);
                channel.setDescription("Alerts when a monitored target's latency or packet loss crosses your threshold");
                nm.createNotificationChannel(channel);
            }
        }
    }
}
