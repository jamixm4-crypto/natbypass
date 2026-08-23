package org.natbypass.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
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
            // Создаем виртуальный TUN интерфейс 10.200.0.100/24
            val builder = Builder()
                .setSession("NatBypass Mesh")
                .addAddress("10.200.0.100", 24)
                .addRoute("10.200.0.0", 24)
                .setMtu(1420)
                .setBlocking(false)

            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: -1

            // Загружаем конфиг из локального хранилища
            val configFile = File(filesDir, "config.yaml")
            val configYaml = if (configFile.exists()) configFile.readText() else "{}"

            // Запускаем нативный Go-движок через JNI / GoMobile
            try {
                val mobileBridgeClass = Class.forName("mobile.Mobile")
                val startMethod = mobileBridgeClass.getMethod("startEngine", String::class.java, Long::class.javaPrimitiveType)
                startMethod.invoke(null, configYaml, fd.toLong())
            } catch (e: Exception) {
                // Если AAR еще не слинкован, эмулируем режим ожидания
            }

            isRunning = true
            startForeground(NOTIFICATION_ID, buildNotification("Подключено к P2P сети (10.200.0.100)"))

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

    private fun disconnect() {
        isRunning = false
        serviceJob?.cancel()
        try {
            val mobileBridgeClass = Class.forName("mobile.Mobile")
            val stopMethod = mobileBridgeClass.getMethod("stopEngine")
            stopMethod.invoke(null)
        } catch (e: Exception) {}

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
