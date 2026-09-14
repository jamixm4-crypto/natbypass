package org.natbypass.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.json.JSONObject
import java.util.Locale

import org.natbypass.app.R
import org.natbypass.app.ui.MainActivity
import java.io.File

class NatBypassVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Raw TUN fd сохранённый после detachFd() для явного закрытия в disconnect() (BUG-A1 fix) */
    private var tunRawFd: Int = -1

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var screenReceiver: BroadcastReceiver? = null

    companion object {
        const val TAG = "NatBypassVpn"
        const val ACTION_CONNECT = "org.natbypass.app.CONNECT"
        const val ACTION_RECONNECT = "org.natbypass.app.RECONNECT"
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

    private fun startForegroundCompat(notification: Notification) {
        try {
            if (Build.VERSION.SDK_INT >= 34) { // Android 14+ (API 34, 35, 36)
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or
                        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) { // Android 10-13 (API 29-33)
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "startForegroundCompat fallback: ${t.message}")
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID,
                        notification,
                        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notification)
                }
            } catch (t2: Throwable) {
                Log.e(TAG, "startForeground completely failed: ${t2.message}")
                try {
                    @Suppress("DEPRECATION")
                    startForeground(NOTIFICATION_ID, notification)
                } catch (_: Throwable) {}
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when (action) {
            ACTION_CONNECT -> {
                val initialNotif = buildNotification("Подключение к P2P меш-сети...", showDisconnect = true)
                startForegroundCompat(initialNotif)
                serviceScope.launch(Dispatchers.IO) {
                    connect(forceReconfigure = false)
                }
            }
            ACTION_RECONNECT -> {
                val initialNotif = buildNotification("Переподключение...", showDisconnect = true)
                startForegroundCompat(initialNotif)
                serviceScope.launch(Dispatchers.IO) {
                    connect(forceReconfigure = true)
                }
            }
            ACTION_DISCONNECT -> {
                serviceScope.launch(Dispatchers.IO) {
                    disconnect()
                    stopSelf()
                }
            }
            else -> {
                if (!isRunning) {
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun calculateSubnet(ip: String, prefix: Int): String {
        return try {
            val parts = ip.split(".").map { it.toInt() }
            if (parts.size != 4) return "10.1.2.0"
            val ipInt = (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
            val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
            val netInt = ipInt and mask
            "${(netInt ushr 24) and 0xFF}.${(netInt ushr 16) and 0xFF}.${(netInt ushr 8) and 0xFF}.${netInt and 0xFF}"
        } catch (_: Exception) {
            "10.1.2.0"
        }
    }

    private fun connect(forceReconfigure: Boolean = false) {
        if (isRunning && !forceReconfigure) return

        try {
            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            val configFile = File(filesDir, "config.yaml")
            val configYaml = if (configFile.exists()) configFile.readText() else "{}"
            val prefVip = prefs.getString("virtual_ip", "")?.trim() ?: ""

            var resolvedVip = ""
            if (prefVip.isNotEmpty() && prefVip.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+(/\\d+)?$"))) {
                resolvedVip = prefVip
            } else {
                resolvedVip = org.natbypass.app.util.MobileBridge.resolveConfigVirtualIP(configYaml).trim()
            }
            if (resolvedVip.isEmpty()) {
                resolvedVip = org.natbypass.app.util.MobileBridge.getVirtualIP().trim()
            }

            val parsedVip = resolvedVip.substringBefore("/").trim()
            val currentVip = if (parsedVip.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))) parsedVip else "100.64.200.10"
            val prefix = resolvedVip.substringAfter("/", "24").toIntOrNull() ?: 24

            try {
                org.natbypass.app.util.MobileBridge.setVirtualIP("$currentVip/$prefix")
            } catch (_: Throwable) {}

            val notif = buildNotification("Подключено к P2P сети ($currentVip)", showDisconnect = true)
            try {
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(NOTIFICATION_ID, notif)
            } catch (t: Throwable) {
                Log.w(TAG, "Notification update error: ${t.message}")
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
            registerNetworkCallback()

            if (screenReceiver == null) {
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(context: Context?, intent: Intent?) {
                        if (intent?.action == Intent.ACTION_SCREEN_ON && isRunning) {
                            serviceScope.launch {
                                try {
                                    val sockFd = org.natbypass.app.util.MobileBridge.getUDPSocketFd()
                                    if (sockFd > 0) protect(sockFd)
                                    org.natbypass.app.util.MobileBridge.refreshPublicIP()
                                } catch (_: Throwable) {}
                            }
                        }
                    }
                }
                try {
                    registerReceiver(receiver, IntentFilter(Intent.ACTION_SCREEN_ON))
                    screenReceiver = receiver
                } catch (e: Throwable) {
                    Log.w(TAG, "registerReceiver SCREEN_ON error: ${e.message}")
                }
            }

            val selectedExitNode = prefs.getString("selected_exit_node", "") ?: ""
            val useExitNode = selectedExitNode.isNotEmpty()
            org.natbypass.app.util.MobileBridge.selectExitNode(selectedExitNode)

            val builder = Builder()
                .setSession("NatBypass")
                .addAddress(currentVip, prefix)
                .setMtu(1420)
                .setBlocking(true)

            if (!useExitNode) {
                builder.allowBypass()
            }

            try {
                // Исключаем само приложение NatBypass из VPN-туннеля.
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication error: ${e.message}")
            }

            try { builder.allowFamily(android.system.OsConstants.AF_INET) } catch (_: Throwable) {}

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                try { builder.setMetered(false) } catch (_: Throwable) {}
            }

            val meshSubnet = calculateSubnet(currentVip, prefix)

            if (useExitNode) {
                try {
                    builder.addRoute("0.0.0.0", 0)
                    Log.i(TAG, "ExitNode default route 0.0.0.0/0 added")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to add default IPv4 route: ${e.message}")
                }
                // Прямой маршрут к меш-подсети рядом с дефолтным шлюзом
                try { builder.addRoute(meshSubnet, prefix) } catch (_: Exception) {}
                if (meshSubnet != "100.64.200.0") {
                    try { builder.addRoute("100.64.200.0", 24) } catch (_: Exception) {}
                }
                if (meshSubnet != "10.1.1.0") {
                    try { builder.addRoute("10.1.1.0", 24) } catch (_: Exception) {}
                }

                // Надежные IPv4 DNS (только для полного туннеля через Exit Node)
                try {
                    builder.addDnsServer("1.1.1.1")
                    builder.addDnsServer("8.8.8.8")
                } catch (e: Exception) { Log.w(TAG, "addDnsServer error: ${e.message}") }
            } else {
                try {
                    builder.addRoute(meshSubnet, prefix)
                    Log.i(TAG, "Mesh route $meshSubnet/$prefix added")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to add mesh route: ${e.message}")
                }
                if (meshSubnet != "100.64.200.0") {
                    try { builder.addRoute("100.64.200.0", 24) } catch (_: Exception) {}
                }
                if (meshSubnet != "10.1.1.0") {
                    try { builder.addRoute("10.1.1.0", 24) } catch (_: Exception) {}
                }

                // ВНИМАНИЕ: В режиме сплит-туннеля (без Exit Node):
                // 1) НЕ добавляем маршрут 100.64.0.0/10! Это диапазон CGNAT сотовых операторов (LTE/5G),
                // его добавление перехватывает мобильный интернет и ломает сеть на телефоне.
                // 2) НЕ вызываем builder.addDnsServer()! Иначе Android перенаправит ВЕСЬ системный DNS в TUN интерфейс.
            }


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
                            Log.i(TAG, "Route $ip/$prefix added")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to add route $subnet: ${e.message}")
                        }
                    }
                }
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "builder.establish() returned NULL")
                disconnect()
                stopSelf()
                try {
                    sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
                        putExtra("state", "error")
                        putExtra("error", "Не удалось создать VPN TUN-интерфейс")
                    })
                } catch (_: Throwable) {}
                return
            }

            // setUnderlyingNetworks ОБЯЗАН вызываться ПОСЛЕ establish()!
            // Это сообщает Android, что VPN работает поверх физического интерфейса (Wi-Fi/LTE)
            // и весь обычный трафик без маршрутов в VPN направляется в физическую сеть без разрыва интернета.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                try {
                    val activeNet = cm.activeNetwork
                    if (activeNet != null) {
                        val caps = cm.getNetworkCapabilities(activeNet)
                        if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                            setUnderlyingNetworks(arrayOf(activeNet))
                            Log.i(TAG, "setUnderlyingNetworks successfully applied physical network after establish()")
                        } else {
                            setUnderlyingNetworks(null)
                        }
                    } else {
                        setUnderlyingNetworks(null)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "setUnderlyingNetworks error: ${e.message}")
                }
            }
            // detachFd() передает владение дескриптором файловому объекту Go (os.File).
            // Сохраняем raw fd отдельно, чтобы disconnect() мог закрыть его через Os.close()
            // даже после того, как Go взял владение (BUG-A1 fix).
            val fd = pfd.detachFd()
            tunRawFd = fd
            vpnInterface = null
            Log.i(TAG, "VPN TUN established! detached fd=$fd, tunRawFd=$tunRawFd, VIP=$currentVip")

            val startRes = org.natbypass.app.util.MobileBridge.startEngine(configYaml, fd)
            if (startRes != "OK") {
                Log.e(TAG, "MobileBridge.startEngine failed: $startRes")
                disconnect()
                stopSelf()
                try {
                    sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
                        putExtra("state", "error")
                        putExtra("error", startRes)
                    })
                } catch (_: Throwable) {}
                return
            }
            val updatedYaml = org.natbypass.app.util.MobileBridge.getConfigYAML()
            if (updatedYaml.isNotEmpty() && updatedYaml != "{}") {
                try { configFile.writeText(updatedYaml) } catch (_: Throwable) {}
            }
            if (selectedExitNode.isNotEmpty()) {
                org.natbypass.app.util.MobileBridge.selectExitNode(selectedExitNode)
            }

            // Защита сокета UDP от зацикливания маршрутизации (критично для Android 14/15/16)
            try {
                val sockFd: Int = org.natbypass.app.util.MobileBridge.getUDPSocketFd()
                if (sockFd > 0) {
                    val ok: Boolean = protect(sockFd)
                    Log.i(TAG, "VpnService.protect($sockFd) applied: $ok")
                }
            } catch (t: Throwable) {
                Log.w(TAG, "protect socket error: ${t.message}")
            }

            isRunning = true

            try {
                sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
                    putExtra("state", "connected")
                    putExtra("vip", currentVip)
                })
            } catch (_: Throwable) {}

            serviceScope.launch {
                delay(500)
                org.natbypass.app.util.MobileBridge.refreshPublicIP()
            }

            serviceJob = serviceScope.launch {
                var lastTx = 0L
                var lastRx = 0L
                var lastTs = System.currentTimeMillis()
                while (isActive && isRunning) {
                    delay(3000)
                    if (!isRunning) break
                    try {
                        val statJson = org.natbypass.app.util.MobileBridge.getTrafficStats()
                        val obj = JSONObject(statJson)
                        val tx = obj.optLong("tx_bytes", 0L)
                        val rx = obj.optLong("rx_bytes", 0L)
                        val now = System.currentTimeMillis()
                        val dt = (now - lastTs) / 1000f
                        val txSpeed = if (dt >= 1.0f && tx >= lastTx) ((tx - lastTx) / dt) else 0f
                        val rxSpeed = if (dt >= 1.0f && rx >= lastRx) ((rx - lastRx) / dt) else 0f
                        lastTx = tx
                        lastRx = rx
                        lastTs = now

                        val txMb = tx / (1024f * 1024f)
                        val rxMb = rx / (1024f * 1024f)
                        val txSpeedStr = if (txSpeed >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", txSpeed / (1024 * 1024)) else String.format(Locale.US, "%.0f KB/s", txSpeed / 1024)
                        val rxSpeedStr = if (rxSpeed >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", rxSpeed / (1024 * 1024)) else String.format(Locale.US, "%.0f KB/s", rxSpeed / 1024)

                        val updatedNotif = buildNotification(
                            "VIP: $currentVip • ↑$txSpeedStr ↓$rxSpeedStr (Σ ${String.format(Locale.US, "%.1f", txMb + rxMb)} MB)",
                            showDisconnect = true
                        )
                        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        nm.notify(NOTIFICATION_ID, updatedNotif)
                    } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "connect failed", e)
            disconnect()
            stopSelf()
        }
    }

    private fun disconnect() {
        if (!isRunning && tunRawFd <= 0 && vpnInterface == null && wakeLock == null && wifiLock == null && networkCallback == null) return
        isRunning = false
        serviceJob?.cancel()
        serviceJob = null

        // 1. Мгновенно отключаем TUN в Go
        try { org.natbypass.app.util.MobileBridge.detachTUN() } catch (_: Throwable) {}

        // 2. Явно закрываем raw TUN fd через системный ParcelFileDescriptor
        try {
            val rawFd = tunRawFd
            if (rawFd > 0) {
                try {
                    android.os.ParcelFileDescriptor.adoptFd(rawFd).close()
                } catch (_: Throwable) {
                    try {
                        val fdObj = java.io.FileDescriptor()
                        val field = java.io.FileDescriptor::class.java.getDeclaredField("descriptor")
                        field.isAccessible = true
                        field.setInt(fdObj, rawFd)
                        android.system.Os.close(fdObj)
                    } catch (_: Throwable) {}
                }
                Log.i(TAG, "TUN fd=$rawFd closed via adoptFd (BUG-A1 fix)")
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Close tunRawFd failed: ${e.message}")
        }
        tunRawFd = -1

        try { vpnInterface?.close() } catch (_: Throwable) {}
        vpnInterface = null

        // 3. МГНОВЕННО снимаем Foreground и гасим уведомление (значок VPN в шторке исчезает сразу)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (_: Throwable) {}

        try {
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(NOTIFICATION_ID)
            Log.i(TAG, "Notification $NOTIFICATION_ID cancelled immediately")
        } catch (_: Throwable) {}

        // 4. Оповещаем UI
        try {
            sendBroadcast(Intent("org.natbypass.app.VPN_STATE_CHANGED").apply {
                putExtra("state", "disconnected")
            })
        } catch (_: Throwable) {}

        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Throwable) {}
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Throwable) {}
        wakeLock = null
        wifiLock = null

        try {
            networkCallback?.let {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            }
        } catch (_: Throwable) {}
        networkCallback = null

        try {
            screenReceiver?.let { unregisterReceiver(it) }
        } catch (_: Throwable) {}
        screenReceiver = null

        // 5. Отправляем Leave-маяк асинхронно в фоне, чтобы задержки сети не подвешивали UI/отключение
        serviceScope.launch(Dispatchers.IO) {
            try { org.natbypass.app.util.MobileBridge.sendOfflineBeacon() } catch (_: Throwable) {}
        }
    }

    private var currentPhysicalNetwork: Network? = null
    private var lastNetworkChangeTs = 0L

    private fun handleNetworkChange(network: Network?, forceRebind: Boolean = false) {
        if (!isRunning) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        var isVpn = false
        if (network != null) {
            try {
                val caps = cm.getNetworkCapabilities(network)
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    isVpn = true
                }
            } catch (_: Throwable) {}
        }
        if (isVpn) return // Never bind or rebind to VPN virtual interface

        val physicalChanged = (network != currentPhysicalNetwork)
        currentPhysicalNetwork = network

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            try {
                if (network != null) {
                    setUnderlyingNetworks(arrayOf(network))
                } else {
                    setUnderlyingNetworks(null)
                }
            } catch (_: Exception) {}
        }

        // Only rebind UDP socket if physical network actually changed (e.g. Wi-Fi <-> Cellular)
        if (physicalChanged || forceRebind) {
            val now = System.currentTimeMillis()
            if (now - lastNetworkChangeTs < 1000) return
            lastNetworkChangeTs = now

            serviceScope.launch(Dispatchers.IO) {
                try {
                    val newFd = org.natbypass.app.util.MobileBridge.rebindSockets()
                    if (newFd > 0) {
                        val ok = protect(newFd)
                        Log.i(TAG, "🔄 Роуминг сети: перепривязан и защищен UDP сокет fd=$newFd ($ok)")
                    } else {
                        val sockFd = org.natbypass.app.util.MobileBridge.getUDPSocketFd()
                        if (sockFd > 0) protect(sockFd)
                    }
                } catch (t: Throwable) {
                    Log.w(TAG, "Ошибка перепривязки сокета при смене сети: ${t.message}")
                }
                org.natbypass.app.util.MobileBridge.refreshPublicIP()
            }
        }
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                handleNetworkChange(network, forceRebind = true)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, networkCapabilities)
                if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                handleNetworkChange(network, forceRebind = false)
            }

            override fun onLost(network: Network) {
                super.onLost(network)
                serviceScope.launch {
                    delay(300)
                    handleNetworkChange(null, forceRebind = true)
                }
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(cb)
            } else {
                val request = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
                cm.registerNetworkCallback(request, cb)
            }
            networkCallback = cb
        } catch (e: Exception) { Log.w(TAG, "registerNetworkCallback error: ${e.message}") }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN отозван системой")
        disconnect()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        disconnect()
        serviceScope.cancel()
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
                enableVibration(false)
                enableLights(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String, showDisconnect: Boolean = true): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            action = Intent.ACTION_MAIN
            addCategory(Intent.CATEGORY_LAUNCHER)
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
            .setShowWhen(false)
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)

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
