package org.natbypass.app.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.MY_PACKAGE_REPLACED") {
            val prefs = context.getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            val autoStart = prefs.getBoolean("auto_start_on_boot", false)
            if (autoStart) {
                val serviceIntent = Intent(context, NatBypassVpnService::class.java).apply {
                    action = NatBypassVpnService.ACTION_CONNECT
                }
                context.startService(serviceIntent)
            }
        }
    }
}
