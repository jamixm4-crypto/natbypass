package org.natbypass.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.natbypass.app.R
import org.natbypass.app.ui.MainActivity
import java.io.File

class NatBypassVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.Default)

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    companion object {
        const val TAG = "NatBypassVpn"
        const val ACTION_CONNECT = "org.natbypass.app.CONNECT"
        const val ACTION_DISCONNECT = "org.natbypass.app.DISCONNECT"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "natbypass_vpn_channel"
        var isRunning = false
            private set
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                disconnect()
                stopSelf()
            }
            else -> {
                connect()
            }
        }
        return START_STICKY
    }

    private fun connect() {
        if (isRunning) return

        try {
            var rawVip = org.natbypass.app.util.MobileBridge.getVirtualIP().trim()
            if (rawVip.contains("/")) rawVip = rawVip.substringBefore("/")
            val currentVip = if (rawVip.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))) rawVip else "100.64.200.10"

            val notif = buildNotification("Подключено к P2P сети ($currentVip)")
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID,
                        notif,
                        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notif)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "startForeground fallback: ${t.message}")
                try { startForeground(NOTIFICATION_ID, notif) } catch (_: Throwable) {}
            }

            // в”Ђв”Ђ WakeLock: PARTIAL_WAKE_LOCK СѓРґРµСЂР¶РёРІР°РµС‚ CPU РІ Р°РєС‚РёРІРЅРѕРј СЃРѕСЃС‚РѕСЏРЅРёРё РІ С„РѕРЅРµ
            try {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "NatBypass::P2PWakeLock").also { lock ->
                    lock.acquire(12 * 60 * 60 * 1000L)
                }
            } catch (e: Exception) {
                Log.w(TAG, "WakeLock acquire error: ${e.message}")
            }

            // в”Ђв”Ђ WifiLock: HIGH_PERF СЂРµР¶РёРј РґР»СЏ РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅРёСЏ СЌРЅРµСЂРіРѕСЃР±РµСЂРµРіР°СЋС‰РµРіРѕ СЃРЅР° Wi-Fi
            try {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION")
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "NatBypass::WifiLock").also {
                    it.acquire()
                }
            } catch (e: Exception) {
                Log.w(TAG, "WifiLock acquire error: ${e.message}")
            }

            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                try {
                    cm.activeNetwork?.let { setUnderlyingNetworks(arrayOf(it)) }
                } catch (e: Exception) {
                    Log.w(TAG, "setUnderlyingNetworks error: ${e.message}")
                }
            }

            registerNetworkCallback()

            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            val selectedExitNode = prefs.getString("selected_exit_node", "") ?: ""
            val useExitNode = selectedExitNode.isNotEmpty()

            // РЎРѕР·РґР°РµРј СЃРёСЃС‚РµРјРЅС‹Р№ РІРёСЂС‚СѓР°Р»СЊРЅС‹Р№ TUN РёРЅС‚РµСЂС„РµР№СЃ (Split-Tunneling)
            val builder = Builder()
                .setSession("NatBypass")
                .addAddress(currentVip, 24)
                .setMtu(1420)
                .setBlocking(false)
                .allowBypass()

            // РСЃРєР»СЋС‡Р°РµРј СЃР°РјРѕ РїСЂРёР»РѕР¶РµРЅРёРµ NatBypass РёР· VPN РґР»СЏ РїСЂСЏРјРѕРіРѕ РґРѕСЃС‚СѓРїР° Рє STUN, MQTT Рё UDP-СЃРѕРєРµС‚Р°Рј Р±РµР· РїРµС‚РµР»СЊ
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication error: ${e.message}")
            }

            try {
                builder.allowFamily(android.system.OsConstants.AF_INET)
            } catch (_: Throwable) {}

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                try {
                    builder.setMetered(false)
                } catch (_: Throwable) {}
            }

            if (useExitNode) {
                // Exit Node СЂРµР¶РёРј: РІРµСЃСЊ РёРЅС‚РµСЂРЅРµС‚-С‚СЂР°С„РёРє + DNS С‡РµСЂРµР· VPN
                builder.addRoute("0.0.0.0", 0)
                try {
                    builder.addDnsServer("1.1.1.1")
                    builder.addDnsServer("8.8.8.8")
                } catch (e: Exception) {
                    Log.w(TAG, "addDnsServer error: ${e.message}")
                }
            } else {
                // Mesh P2P СЂРµР¶РёРј: РўРћР›Р¬РљРћ РїРѕРґСЃРµС‚СЊ 100.64.200.0/24
                // РќР• РґРѕР±Р°РІР»СЏРµРј DNS СЃРµСЂРІРµСЂС‹ вЂ” Android Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РјР°СЂС€СЂСѓС‚РёР·РёСЂСѓРµС‚ DNS С‡РµСЂРµР· VPN
                // РµСЃР»Рё СѓРєР°Р·Р°С‚СЊ addDnsServer(), С‡С‚Рѕ СѓР±РёРІР°РµС‚ РёРЅС‚РµСЂРЅРµС‚ РІ split-tunnel СЂРµР¶РёРјРµ
                builder.addRoute("100.64.200.0", 24)
            }

            // РђРЅРѕРЅСЃРёСЂРѕРІР°РЅРЅС‹Рµ РїРѕРґСЃРµС‚Рё (РЅР°РїСЂРёРјРµСЂ, 192.168.1.0/24)
            val advSubnets = prefs.getString("adv_subnets", "") ?: ""
            if (advSubnets.isNotEmpty()) {
                for (subnet in advSubnets.split(",")) {
                    val s = subnet.trim()
                    if (s.contains("/")) {
                        val parts = s.split("/")
                        val ip = parts[0]
                        val prefix = parts[1].toIntOrNull() ?: 24
                        try {
                            builder.addRoute(ip, prefix)
                        } catch (e: Exception) {
                            Log.w(TAG, "addRoute error for $subnet: ${e.message}")
                        }
                    }
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "builder.establish() returned NULL - VPN permission revoked or another VPN is active")
                stopSelf()
                return
            }
            val fd = vpnInterface?.fd ?: -1
            Log.i(TAG, "VPN TUN adapter established! fd=$fd, VIP=$currentVip")

            // Р—Р°РіСЂСѓР¶Р°РµРј РєРѕРЅС„РёРі Рё Р·Р°РїСѓСЃРєР°РµРј / РїСЂРёРІСЏР·С‹РІР°РµРј Go-РґРІРёР¶РѕРє
            val configFile = File(filesDir, "config.yaml")
            val configYaml = if (configFile.exists()) configFile.readText() else "{}"

            org.natbypass.app.util.MobileBridge.startEngine(configYaml, fd)

            isRunning = true

            // Р¤РѕРЅРѕРІС‹Р№ РјРѕРЅРёС‚РѕСЂРёРЅРі СЃРѕСЃС‚РѕСЏРЅРёСЏ
            serviceJob = scope.launch {
                while (isActive) {
                    delay(3000)
                    if (!isRunning) break
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "connect failed", e)
            disconnect()
        }
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    try {
                        setUnderlyingNetworks(arrayOf(network))
                    } catch (_: Exception) {}
                }
                scope.launch {
                    delay(800)
                    org.natbypass.app.util.MobileBridge.refreshPublicIP()
                }
            }
        }
        try {
            cm.registerNetworkCallback(request, cb)
            networkCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback error: ${e.message}")
        }
    }

    private fun disconnect() {
        if (!isRunning && vpnInterface == null) return
        isRunning = false
        serviceJob?.cancel()
        serviceJob = null

        try {
            org.natbypass.app.util.MobileBridge.detachTUN()
        } catch (_: Exception) {}

        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Exception) {}
        wakeLock = null
        wifiLock = null

        try {
            networkCallback?.let {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.unregisterNetworkCallback(it)
            }
        } catch (_: Exception) {}
        networkCallback = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (_: Exception) {}
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notif_channel_desc)
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pOpen = PendingIntent.getActivity(this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE)

        val disconnectIntent = Intent(this, NatBypassVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pDisconnect = PendingIntent.getService(this, 1, disconnectIntent, PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_lock)
            .setContentTitle("NatBypass Mesh VPN")
            .setContentText(statusText)
            .setContentIntent(pOpen)
            .addAction(R.drawable.ic_vpn_lock, "Отключить", pDisconnect)
            .setOngoing(true)
            .build()
    }
}

