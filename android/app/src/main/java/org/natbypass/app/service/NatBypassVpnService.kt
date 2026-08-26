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

    // WakeLock — предотвращает засыпание CPU, чтобы UDP горутины продолжали работать при выключенном экране
    private var wakeLock: PowerManager.WakeLock? = null
    // WifiLock — удерживает Wi-Fi в высокопроизводительном режиме при включённом экране
    private var wifiLock: WifiManager.WifiLock? = null
    // NetworkCallback — автоматически пере-STUN при смене сети (Wi-Fi → LTE и обратно)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    companion object {
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
            val currentVip = org.natbypass.app.util.MobileBridge.getVirtualIP().ifEmpty { "10.200.0.10" }
            val notif = buildNotification("Подключение к P2P сети ($currentVip)...")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notif,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else {
                startForeground(NOTIFICATION_ID, notif)
            }

            // ── WakeLock: PARTIAL_WAKE_LOCK позволяет CPU работать при выключенном экране
            // Это критически важно — без него Android Doze Mode замораживает UDP-горутины
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "NatBypass::P2PWakeLock"
            ).also { lock ->
                lock.acquire(12 * 60 * 60 * 1000L) // max 12 часов, сервис сам освободит при disconnect
            }

            // ── WifiLock: HIGH_PERF режим — снижает latency на Wi-Fi, предотвращает засыпание адаптера
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "NatBypass::WifiLock").also {
                it.acquire()
            }

            // ── NetworkCallback: триггерит re-STUN при переключении сети (Wi-Fi ↔ LTE)
            // Без этого после смены сети STUN-адрес остаётся устаревшим и hole punch не работает
            registerNetworkCallback()

            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            val selectedExitNode = prefs.getString("selected_exit_node", "") ?: ""
            val useExitNode = selectedExitNode.isNotEmpty()

            // Создаем виртуальный TUN интерфейс с динамическим IP сети
            val builder = Builder()
                .setSession("NatBypass")
                .addAddress(currentVip, 24)
                .setMtu(1420)

            if (useExitNode) {
                // Если выбран Exit Node - перенаправляем весь интернет через удаленный узел
                builder.addRoute("0.0.0.0", 0)
                builder.addDnsServer("1.1.1.1")
                builder.addDnsServer("8.8.8.8")
            } else {
                // Только локальная mesh-подсеть
                builder.addRoute("10.200.0.0", 24)
            }

            // Добавляем анонсированные подсети (например, домашняя сеть роутера 192.168.1.0/24)
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
                        } catch (e: Exception) {}
                    }
                }
            }

            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: -1

            // Загружаем конфиг из локального хранилища
            val configFile = File(filesDir, "config.yaml")
            val configYaml = if (configFile.exists()) configFile.readText() else "{}"

            // Запускаем нативный Go-движок через JNI / GoMobile
            org.natbypass.app.util.MobileBridge.startEngine(configYaml, fd)

            isRunning = true
            val manager = getSystemService(NotificationManager::class.java)
            manager.notify(NOTIFICATION_ID, buildNotification("Подключено к P2P сети ($currentVip)"))

            // Фоновый мониторинг состояния
            serviceJob = scope.launch {
                while (isActive) {
                    delay(3000)
                    if (!isRunning) break
                }
            }
        } catch (e: Exception) {
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
                // Сеть изменилась — триггерим пересборку STUN-адреса через 1 секунду
                // (даём сети стабилизироваться перед отправкой нового маяка)
                scope.launch {
                    delay(1000)
                    if (isRunning) {
                        // Уведомляем Go-движок о смене сети через обновление конфигурации
                        // В текущей архитектуре достаточно принудительного переопределения IP
                        org.natbypass.app.util.MobileBridge.refreshPublicIP()
                    }
                }
            }
        }
        cm.registerNetworkCallback(request, cb)
        networkCallback = cb
    }

    private fun disconnect() {
        isRunning = false
        serviceJob?.cancel()
        org.natbypass.app.util.MobileBridge.detachTUN()

        // Освобождаем WakeLock и WifiLock
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        try { if (wifiLock?.isHeld == true) wifiLock?.release() } catch (_: Exception) {}
        wakeLock = null
        wifiLock = null

        // Снимаем регистрацию NetworkCallback
        try {
            networkCallback?.let {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.unregisterNetworkCallback(it)
            }
        } catch (_: Exception) {}
        networkCallback = null

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {}

        stopForeground(STOP_FOREGROUND_REMOVE)
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
            .setContentTitle("NatBypass")
            .setContentText(statusText)
            .setContentIntent(pOpen)
            .addAction(R.drawable.ic_vpn_lock, "Отключить", pDisconnect)
            .setOngoing(true)
            .build()
    }
}

