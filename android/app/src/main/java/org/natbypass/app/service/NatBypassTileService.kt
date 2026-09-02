package org.natbypass.app.service

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import org.natbypass.app.ui.MainActivity

@RequiresApi(Build.VERSION_CODES.N)
class NatBypassTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        val running = NatBypassVpnService.isRunning
        if (running) {
            val intent = Intent(this, NatBypassVpnService::class.java).apply {
                action = NatBypassVpnService.ACTION_DISCONNECT
            }
            startService(intent)
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // Требуется подтверждение VPN в Activity
                val appIntent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivityAndCollapse(appIntent)
            } else {
                val intent = Intent(this, NatBypassVpnService::class.java).apply {
                    action = NatBypassVpnService.ACTION_CONNECT
                }
                startService(intent)
            }
        }
        updateTileState()
    }

    private fun updateTileState() {
        val tile = qsTile ?: return
        val running = NatBypassVpnService.isRunning
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        val vip = try {
            org.natbypass.app.util.MobileBridge.getVirtualIP().substringBefore("/").trim().ifEmpty { "Подключено" }
        } catch (_: Exception) { "Подключено" }
        tile.subtitle = if (running) vip else "Отключено"
        tile.updateTile()
    }
}

