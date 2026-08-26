package org.natbypass.app.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.natbypass.app.service.NatBypassVpnService
import org.natbypass.app.util.MobileBridge
import java.io.File

// ── UI State ─────────────────────────────────────────────────────────────────

enum class ConnectionState {
    DISCONNECTED, CONNECTING, CONNECTED_P2P, CONNECTED_RELAY
}

data class PeerUiModel(
    val id: String,
    val displayName: String,
    val virtualIp: String,
    val platform: String,
    val channelType: String,   // "p2p" | "relay" | "offline"
    val pingMs: Long,
    val isOnline: Boolean,
    val isExitNode: Boolean,
    val natType: String,
)

data class ProfileUiModel(
    val id: String,
    val name: String,
    val mqttTopic: String,
    val mqttBroker: String,
    val tgToken: String,
    val tgChat: Long,
    val tgProxy: String,
    val isActive: Boolean,
)

data class MainUiState(
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val virtualIp: String = "",
    val publicIp: String = "",
    val stunAddr: String = "",
    val activeChannel: String = "",
    val natType: String = "",
    val avgRttMs: Long = 0L,
    val peers: List<PeerUiModel> = emptyList(),
    val onlinePeers: Int = 0,
    val totalPeers: Int = 0,
    val activeProfileName: String = "",
    val profiles: List<ProfileUiModel> = emptyList(),
    val errorMessage: String? = null,
    val isRefreshing: Boolean = false,
)

// ── ViewModel ─────────────────────────────────────────────────────────────────

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private val prefs get() = getApplication<Application>()
        .getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

    init {
        startPolling()
        ensureEngineStarted()
    }

    private fun ensureEngineStarted() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val configFile = File(getApplication<Application>().filesDir, "config.yaml")
                val configYaml = if (configFile.exists() && configFile.length() > 5) configFile.readText() else "{}"
                MobileBridge.startEngine(configYaml, 0)
                val yaml = MobileBridge.getConfigYAML()
                if (yaml.isNotEmpty() && yaml != "{}") configFile.writeText(yaml)
            } catch (_: Exception) {}
        }
    }

    private fun startPolling() {
        viewModelScope.launch {
            while (isActive) {
                refreshStatus()
                delay(2000)
            }
        }
    }

    private suspend fun refreshStatus() = withContext(Dispatchers.IO) {
        try {
            val statusJson  = MobileBridge.getStatusJSON()
            val peersJson   = MobileBridge.getPeersJSON()
            val profilesJson= MobileBridge.getProfilesJSON()
            parseAndEmit(statusJson, peersJson, profilesJson)
        } catch (_: Exception) {}
    }

    private fun parseAndEmit(statusJson: String, peersJson: String, profilesJson: String) {
        // --- Status ---
        var publicIp = ""
        var stunAddr = ""
        var virtualIp = MobileBridge.getVirtualIP().ifEmpty { "10.200.0.10" }
        var activeChannel = ""
        var natType = ""
        var isEngineRunning = false
        try {
            val obj = JSONObject(statusJson)
            isEngineRunning = obj.optBoolean("running", false)
            publicIp   = obj.optString("public_ip", "")
            stunAddr   = obj.optString("stun_addr", "")
            virtualIp  = obj.optString("virtual_ip", virtualIp)
            activeChannel = obj.optString("channel", "")
            natType    = obj.optString("nat_type", "")
        } catch (_: Exception) {}

        val vpnActive = isEngineRunning || NatBypassVpnService.isRunning

        // --- Peers ---
        val peers = mutableListOf<PeerUiModel>()
        var onlineCount = 0
        var totalRtt = 0L
        var rttCount = 0
        try {
            val arr = JSONArray(peersJson)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val id  = obj.optString("device_id", obj.optString("DeviceID", "unknown-$i"))
                val savedNick = prefs.getString("nick_$id", "") ?: ""
                val nick = savedNick.ifEmpty {
                    obj.optString("nickname", obj.optString("Nickname", ""))
                }
                val displayName = when {
                    nick.isNotEmpty() && !nick.equals(id, ignoreCase = true) -> "$nick ($id)"
                    nick.isNotEmpty() -> nick
                    else -> id
                }
                val vip      = obj.optString("virtual_ip", obj.optString("VirtualIP", ""))
                val isOnline = obj.optBoolean("online", obj.optBoolean("Online", true))
                val isExit   = obj.optBoolean("is_exit_node", false) || obj.optBoolean("IsExitNode", false)
                val pingMs   = obj.optLong("ping_ms", obj.optLong("PingMs", 0L))
                val directP2p = obj.optBoolean("direct_p2p", false)
                val peerNat  = obj.optString("nat_type", "")

                var plat = obj.optString("platform", obj.optString("Platform", ""))
                if (plat.isEmpty()) {
                    val lower = id.lowercase()
                    plat = when {
                        lower.contains("android") -> "Android"
                        lower.contains("cloud") || lower.contains("linux") -> "Linux"
                        lower.contains("keenetic") || lower.contains("router") -> "Router"
                        else -> "Windows"
                    }
                }

                val channelType = when {
                    !isOnline -> "offline"
                    directP2p -> "p2p"
                    else -> "relay"
                }

                if (isOnline) {
                    onlineCount++
                    if (pingMs > 0) { totalRtt += pingMs; rttCount++ }
                }

                peers.add(PeerUiModel(
                    id          = id,
                    displayName = displayName,
                    virtualIp   = vip,
                    platform    = plat,
                    channelType = channelType,
                    pingMs      = pingMs,
                    isOnline    = isOnline,
                    isExitNode  = isExit,
                    natType     = peerNat,
                ))
            }
        } catch (_: Exception) {}

        // --- Profiles ---
        val profilesList = mutableListOf<ProfileUiModel>()
        var activeProfileName = ""
        try {
            val pObj = JSONObject(profilesJson)
            val activeProf = pObj.optJSONObject("active_profile")
            if (activeProf != null) {
                activeProfileName = activeProf.optString("name", "Основная сеть")
                profilesList.add(ProfileUiModel(
                    id         = activeProf.optString("id", ""),
                    name       = activeProfileName,
                    mqttTopic  = activeProf.optString("mqtt_topic", ""),
                    mqttBroker = activeProf.optString("mqtt_broker", "tcp://broker.emqx.io:1883"),
                    tgToken    = activeProf.optString("tg_token", ""),
                    tgChat     = activeProf.optLong("tg_chat_id", 0L),
                    tgProxy    = activeProf.optString("tg_proxy", ""),
                    isActive   = true,
                ))
            }
            val allProfs = pObj.optJSONArray("profiles")
            if (allProfs != null) {
                for (i in 0 until allProfs.length()) {
                    val p = allProfs.getJSONObject(i)
                    if (p.optBoolean("is_active", false)) continue
                    profilesList.add(ProfileUiModel(
                        id         = p.optString("id", ""),
                        name       = p.optString("name", ""),
                        mqttTopic  = p.optString("mqtt_topic", ""),
                        mqttBroker = p.optString("mqtt_broker", "tcp://broker.emqx.io:1883"),
                        tgToken    = p.optString("tg_token", ""),
                        tgChat     = p.optLong("tg_chat_id", 0L),
                        tgProxy    = p.optString("tg_proxy", ""),
                        isActive   = false,
                    ))
                }
            }
        } catch (_: Exception) {}

        // --- Connection State ---
        val connState = when {
            !vpnActive -> ConnectionState.DISCONNECTED
            peers.any { it.channelType == "p2p" } -> ConnectionState.CONNECTED_P2P
            else -> ConnectionState.CONNECTED_RELAY
        }

        val avgRtt = if (rttCount > 0) totalRtt / rttCount else 0L

        _uiState.update {
            it.copy(
                connectionState   = connState,
                virtualIp         = virtualIp,
                publicIp          = publicIp,
                stunAddr          = stunAddr,
                activeChannel     = activeChannel,
                natType           = natType,
                avgRttMs          = avgRtt,
                peers             = peers,
                onlinePeers       = onlineCount,
                totalPeers        = peers.size,
                activeProfileName = activeProfileName,
                profiles          = profilesList,
            )
        }
    }

    // ── VPN control ───────────────────────────────────────────────────────────

    fun onVpnToggleClick(activity: Activity, permissionLauncher: (Intent) -> Unit) {
        val isRunning = prefs.getBoolean("vpn_running", false) || NatBypassVpnService.isRunning
        if (isRunning) {
            stopVpn(activity)
        } else {
            val vpnIntent = VpnService.prepare(activity)
            if (vpnIntent != null) {
                permissionLauncher(vpnIntent)
            } else {
                startVpn(activity)
            }
        }
    }

    fun startVpn(context: Context) {
        val intent = Intent(context, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_CONNECT
        }
        androidx.core.content.ContextCompat.startForegroundService(context, intent)
        prefs.edit().putBoolean("vpn_running", true).apply()
        _uiState.update { it.copy(connectionState = ConnectionState.CONNECTING) }
    }

    fun stopVpn(context: Context) {
        val intent = Intent(context, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
        prefs.edit().putBoolean("vpn_running", false).apply()
        _uiState.update { it.copy(connectionState = ConnectionState.DISCONNECTED) }
    }

    // ── Peer actions ──────────────────────────────────────────────────────────

    fun pingPeer(peerId: String, onResult: (Long) -> Unit) {
        viewModelScope.launch {
            val rtt = withContext(Dispatchers.IO) { MobileBridge.pingPeer(peerId) }
            onResult(rtt)
            if (rtt >= 0) refreshStatus()
        }
    }

    fun setExitNode(context: Context, peerId: String) {
        prefs.edit().putString("selected_exit_node", peerId).apply()
        MobileBridge.selectExitNode(peerId)
    }

    fun deletePeer(peerId: String) {
        MobileBridge.clearPeers()
        viewModelScope.launch { refreshStatus() }
    }

    fun setPeerNickname(peerId: String, nick: String) {
        prefs.edit().putString("nick_$peerId", nick).apply()
        viewModelScope.launch { refreshStatus() }
    }

    // ── Profile actions ───────────────────────────────────────────────────────

    fun switchProfile(profileId: String, context: Context) {
        if (MobileBridge.switchProfile(profileId)) {
            saveConfigToDisk(context)
            viewModelScope.launch { refreshStatus() }
        }
    }

    fun createProfile(
        context: Context, name: String, broker: String, topic: String,
        tgToken: String, tgChat: Long, tgProxy: String
    ) {
        MobileBridge.createProfile(name, broker, topic, "", "", tgToken, tgChat, tgProxy, "dpi", true)
        saveConfigToDisk(context)
        viewModelScope.launch { refreshStatus() }
    }

    fun updateProfile(
        context: Context, id: String, name: String, broker: String, topic: String,
        tgToken: String, tgChat: Long, tgProxy: String
    ) {
        MobileBridge.updateProfile(id, name, broker, topic, "", "", tgToken, tgChat, tgProxy, "dpi")
        saveConfigToDisk(context)
        viewModelScope.launch { refreshStatus() }
    }

    fun deleteProfile(context: Context, profileId: String) {
        MobileBridge.deleteProfile(profileId)
        saveConfigToDisk(context)
        viewModelScope.launch { refreshStatus() }
    }

    fun importProfile(context: Context, uri: String): Boolean {
        val res = MobileBridge.importProfileURI(uri)
        return if (!res.startsWith("ERR:")) {
            saveConfigToDisk(context)
            viewModelScope.launch { refreshStatus() }
            true
        } else false
    }

    fun exportProfileUri(profileId: String): String = MobileBridge.exportProfileURI(profileId)

    fun setAWGPreset(preset: String) = MobileBridge.setAWGPreset(preset)

    fun clearPeers(context: Context) {
        MobileBridge.clearPeers()
        viewModelScope.launch { refreshStatus() }
    }

    private fun saveConfigToDisk(context: Context) {
        try {
            val yaml = MobileBridge.getConfigYAML()
            if (yaml.isNotEmpty() && yaml != "{}") {
                File(context.filesDir, "config.yaml").writeText(yaml)
            }
        } catch (_: Exception) {}
    }
}
