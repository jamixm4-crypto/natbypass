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
        val action = intent?.action
        when (action) {
            ACTION_CONNECT -> {
                connect()
            }
            ACTION_DISCONNECT -> {
                // KEY FIX: Do NOT call stopSelf() immediately here.
                // Instead: gracefully teardown TUN, update notification to "Disconnected",
                // keep the service alive briefly so Android does not dismiss the Activity.
                disconnectGracefully()
            }
            else -> {
                // System restart with null intent — do not auto-reconnect
                if (!isRunning) {
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun connect() {
        if (isRunning) return

        try {
            var rawVip = org.natbypass.app.util.MobileBridge.getVirtualIP().trim()
            if (rawVip.contains("/")) rawVip = rawVip.substringBefore("/")
            val currentVip = if (rawVip.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))) rawVip else "100.64.200.10"

            val notif = buildNotification("Подключено к P2P сети ($currentVip)", showDisconnect = true)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID, notif,
                        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notif)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "startForeground fallback: ${t.message}")
                try { startForeground(NOTIFICATION_ID, notif) } catch (_: Throwable) {}
            }

            try {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "NatBypass::P2PWakeLock").also {
                    it.acquire(12 * 60 * 60 * 1000L)
                }
            } catch (e: Exception) { Log.w(TAG, "WakeLock error: ${e.message}") }

            try {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION")
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "NatBypass::WifiLock").also {
                    it.acquire()
                }
            } catch (e: Exception) { Log.w(TAG, "WifiLock error: ${e.message}") }

            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                try { cm.activeNetwork?.let { setUnderlyingNetworks(arrayOf(it)) } } catch (_: Exception) {}
            }

            registerNetworkCallback()

            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            val selectedExitNode = prefs.getString("selected_exit_node", "") ?: ""
            val useExitNode = selectedExitNode.isNotEmpty()

            val builder = Builder()
                .setSession("NatBypass")
                .addAddress(currentVip, 24)
                .setMtu(1420)
                .setBlocking(false)
                .allowBypass()

            try { builder.allowFamily(android.system.OsConstants.AF_INET) } catch (_: Throwable) {}

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                try { builder.setMetered(false) } catch (_: Throwable) {}
            }

            if (useExitNode) {
                builder.addRoute("0.0.0.0", 0)
                try {
                    builder.addDnsServer("1.1.1.1")
                    builder.addDnsServer("8.8.8.8")
                } catch (e: Exception) { Log.w(TAG, "addDnsServer error: ${e.message}") }
            } else {
                builder.addRoute("100.64.200.0", 24)
            }

            val advSubnets = prefs.getString("adv_subnets", "") ?: ""
            if (advSubnets.isNotEmpty()) {
                for (subnet in advSubnets.split(",")) {
                    val s = subnet.trim()
                    if (s.contains("/")) {
                        val parts = s.split("/")
                        try { builder.addRoute(parts[0], parts[1].toIntOrNull() ?: 24) }
                        catch (e: Exception) { Log.w(TAG, "addRoute error: ${e.message}") }
                    }
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "builder.establish() returned NULL")
                stopSelf()
                return
            }
            val fd = vpnInterface?.fd ?: -1
            Log.i(TAG, "VPN TUN established! fd=$fd, VIP=$currentVip")

            val configFile = File(filesDir, "config.yaml")
            val configYaml = if (configFile.exists()) configFile.readText() else "{}"
            org.natbypass.app.util.MobileBridge.startEngine(configYaml, fd)

            isRunning = true

            serviceJob = scope.launch {
                while (isActive) {
                    delay(3000)
                    if (!isRunning) break
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "connect failed", e)
            disconnectGracefully()
        }
    }

    /**
     * Graceful disconnect: closes TUN, releases locks, detaches foreground notification
     * using STOP_FOREGROUND_DETACH so the PROCESS stays alive and Android does NOT
     * dismiss or minimize MainActivity.
     */
    private fun disconnectGracefully() {
        val wasRunning = isRunning
        isRunning = false
        serviceJob?.cancel()
        serviceJob = null

        try { org.natbypass.app.util.MobileBridge.detachTUN() } catch (_: Exception) {}

        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Exception) {}
        wakeLock = null
        wifiLock = null

        try {
            networkCallback?.let {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            }
        } catch (_: Exception) {}
        networkCallback = null

        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        // CRITICAL: Use STOP_FOREGROUND_DETACH (NOT REMOVE).
        // DETACH keeps the notification alive but detaches it from VpnService lifecycle.
        // REMOVE would destroy the foreground service anchor causing Android to minimize the Activity.
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_DETACH)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(false)
            }
        } catch (_: Exception) {}

        // Update notification to "Disconnected" state
        if (wasRunning) {
            try {
                val nm = getSystemService(NotificationManager::class.java)
                nm.notify(NOTIFICATION_ID, buildNotification("VPN отключён. Нажмите для подключения.", showDisconnect = false))
            } catch (_: Exception) {}
        }

        // Notify MainActivity via broadcast to update UI (connection toggle button etc.)
        sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
            putExtra("state", "disconnected")
        })

        stopSelf()
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
                    try { setUnderlyingNetworks(arrayOf(network)) } catch (_: Exception) {}
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
        } catch (e: Exception) { Log.w(TAG, "registerNetworkCallback error: ${e.message}") }
    }

    override fun onRevoke() {
        // System revoked VPN (another VPN app started, permission removed, etc.)
        // KEY FIX: Do NOT call stopSelf() here — that would kill the Activity.
        // Keep the process alive, close TUN, update notification.
        isRunning = false
        serviceJob?.cancel()
        serviceJob = null

        try { org.natbypass.app.util.MobileBridge.detachTUN() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        // Keep foreground alive with "revoked" status notification
        try {
            val notif = buildNotification("⚠️ VPN отключён системой. Нажмите для переподключения.", showDisconnect = false)
            startForeground(NOTIFICATION_ID, notif)
        } catch (_: Exception) {}

        // Broadcast to Activity to update UI without closing it
        sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
            putExtra("state", "revoked")
        })

        super.onRevoke()  // NO stopSelf() here!
    }

    override fun onDestroy() {
        if (isRunning) {
            disconnectGracefully()
        }
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
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String, showDisconnect: Boolean = true): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pOpen = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_lock)
            .setContentTitle("NatBypass Mesh VPN")
            .setContentText(statusText)
            .setContentIntent(pOpen)
            .setOngoing(showDisconnect)

        if (showDisconnect) {
            val disconnectIntent = Intent(this, NatBypassVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            val pDisconnect = PendingIntent.getService(
                this, 1, disconnectIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(R.drawable.ic_vpn_lock, "Отключить", pDisconnect)
        }

        return builder.build()
    }
}
