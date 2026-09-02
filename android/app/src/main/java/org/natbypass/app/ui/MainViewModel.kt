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

// в”Ђв”Ђ UI State в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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
    val advertisedRoutes: List<String> = emptyList(),
    val isSelectedExitNode: Boolean = false,
)

data class ProfileUiModel(
    val id: String,
    val name: String,
    val mqttTopic: String,
    val mqttBroker: String,
    val virtualIp: String = "",
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
    val txBytes: Long = 0L,
    val rxBytes: Long = 0L,
    val txSpeedBps: Long = 0L,
    val rxSpeedBps: Long = 0L,
    val txHistory: List<Float> = emptyList(),
    val rxHistory: List<Float> = emptyList(),
    val rttHistory: List<Float> = emptyList(),
    val peers: List<PeerUiModel> = emptyList(),
    val onlinePeers: Int = 0,
    val totalPeers: Int = 0,
    val activeProfileName: String = "",
    val profiles: List<ProfileUiModel> = emptyList(),
    val errorMessage: String? = null,
    val isRefreshing: Boolean = false,
)

// ── ViewModel ─────────────────────────────────────────────────────────────

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private var lastTxBytes = 0L
    private var lastRxBytes = 0L
    private var lastStatsTimestamp = 0L
    private var lastTxSpeedBps = 0L
    private var lastRxSpeedBps = 0L

    private val txHistoryBuf = mutableListOf<Float>()
    private val rxHistoryBuf = mutableListOf<Float>()
    private val rttHistoryBuf = mutableListOf<Float>()

    private val prefs get() = getApplication<Application>()
        .getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

    init {
        // Синхронизируем реальное состояние сервиса при старте
        prefs.edit().putBoolean("vpn_running", NatBypassVpnService.isRunning).apply()
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
                val isVpnActive = NatBypassVpnService.isRunning
                delay(if (isVpnActive) 2000L else 5000L)
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
        var virtualIp = MobileBridge.getVirtualIP().ifEmpty { "100.64.200.10" }
        var activeChannel = ""
        var natType = ""
        var isEngineRunning = false
        var txBytes = 0L
        var rxBytes = 0L
        try {
            val obj = JSONObject(statusJson)
            isEngineRunning = obj.optBoolean("running", false)
            publicIp   = obj.optString("public_ip", "")
            stunAddr   = obj.optString("stun_addr", "")
            virtualIp  = obj.optString("virtual_ip", virtualIp)
            activeChannel = obj.optString("channel", "")
            natType    = obj.optString("nat_type", "")
            txBytes    = obj.optLong("tx_bytes", 0L)
            rxBytes    = obj.optLong("rx_bytes", 0L)

            val now = System.currentTimeMillis()
            val dt = if (lastStatsTimestamp > 0) (now - lastStatsTimestamp) / 1000f else 0f
            if (dt >= 1.0f) {
                lastTxSpeedBps = if (txBytes >= lastTxBytes) ((txBytes - lastTxBytes) / dt).toLong() else 0L
                lastRxSpeedBps = if (rxBytes >= lastRxBytes) ((rxBytes - lastRxBytes) / dt).toLong() else 0L
                lastTxBytes = txBytes
                lastRxBytes = rxBytes
                lastStatsTimestamp = now
            }
        } catch (_: Exception) {}


        val vpnActive = NatBypassVpnService.isRunning

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
                val routesList = mutableListOf<String>()
                val routesArr = obj.optJSONArray("advertised_routes") ?: obj.optJSONArray("AdvertisedRoutes")
                if (routesArr != null) {
                    for (rIdx in 0 until routesArr.length()) {
                        val rStr = routesArr.optString(rIdx, "").trim()
                        if (rStr.isNotEmpty()) routesList.add(rStr)
                    }
                }
                val selectedExit = prefs.getString("selected_exit_node", "") ?: ""

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
                    id                 = id,
                    displayName        = displayName,
                    virtualIp          = vip,
                    platform           = plat,
                    channelType        = channelType,
                    pingMs             = pingMs,
                    isOnline           = isOnline,
                    isExitNode         = isExit,
                    natType            = peerNat,
                    advertisedRoutes   = routesList,
                    isSelectedExitNode = (selectedExit.isNotEmpty() && selectedExit == id),
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
                    virtualIp  = activeProf.optString("virtual_ip", ""),
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
                        virtualIp  = p.optString("virtual_ip", ""),
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

        // Обновляем буферы истории скорости и пинга (до 40 точек для плавного графика)
        synchronized(txHistoryBuf) {
            txHistoryBuf.add(lastTxSpeedBps.toFloat())
            if (txHistoryBuf.size > 40) txHistoryBuf.removeAt(0)

            rxHistoryBuf.add(lastRxSpeedBps.toFloat())
            if (rxHistoryBuf.size > 40) rxHistoryBuf.removeAt(0)

            rttHistoryBuf.add(avgRtt.toFloat())
            if (rttHistoryBuf.size > 40) rttHistoryBuf.removeAt(0)
        }

        _uiState.update {
            it.copy(
                connectionState   = connState,
                virtualIp         = virtualIp,
                publicIp          = publicIp,
                stunAddr          = stunAddr,
                activeChannel     = activeChannel,
                natType           = natType,
                avgRttMs          = avgRtt,
                txBytes           = txBytes,
                rxBytes           = rxBytes,
                txSpeedBps        = lastTxSpeedBps,
                rxSpeedBps        = lastRxSpeedBps,
                txHistory         = txHistoryBuf.toList(),
                rxHistory         = rxHistoryBuf.toList(),
                rttHistory        = rttHistoryBuf.toList(),
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
        // Проверяем РЕАЛЬНОЕ состояние запущенной службы
        val isRunning = NatBypassVpnService.isRunning
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
        val appContext = context.applicationContext
        val intent = Intent(appContext, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_DISCONNECT
        }
        try {
            appContext.startService(intent)
        } catch (e: Exception) {
            try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    appContext.startForegroundService(intent)
                }
            } catch (_: Exception) {}
        }
        prefs.edit().putBoolean("vpn_running", false).apply()
        _uiState.update { it.copy(connectionState = ConnectionState.DISCONNECTED) }
    }

    /** Called when VPN disconnects via broadcast from NatBypassVpnService (onRevoke or user disconnect). */
    fun onVpnDisconnectedExternally() {
        prefs.edit().putBoolean("vpn_running", false).apply()
        _uiState.update { it.copy(connectionState = ConnectionState.DISCONNECTED) }
    }

    // в”Ђв”Ђ Peer actions в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fun pingPeer(peerId: String, onResult: (Long) -> Unit) {
        viewModelScope.launch {
            val rtt = withContext(Dispatchers.IO) { MobileBridge.pingPeer(peerId) }
            onResult(rtt)
            if (rtt >= 0) refreshStatus()
        }
    }

    fun toggleSubnetRoute(context: Context, subnet: String): Boolean {
        val current = prefs.getString("adv_subnets", "") ?: ""
        val currentList = current.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
        val isActive = currentList.contains(subnet)
        if (isActive) {
            currentList.remove(subnet)
        } else {
            currentList.add(subnet)
        }
        val newAdv = currentList.joinToString(",")
        prefs.edit().putString("adv_subnets", newAdv).apply()
        
        if (NatBypassVpnService.isRunning) {
            val intent = Intent(context, NatBypassVpnService::class.java).apply {
                action = NatBypassVpnService.ACTION_RECONNECT
            }
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }
        viewModelScope.launch { refreshStatus() }
        return !isActive
    }

    fun toggleExitNode(context: Context, peerId: String): Boolean {
        val current = prefs.getString("selected_exit_node", "") ?: ""
        val newTarget = if (current == peerId) "" else peerId
        prefs.edit().putString("selected_exit_node", newTarget).apply()
        MobileBridge.selectExitNode(newTarget)

        // Р•СЃР»Рё VPN Р°РєС‚РёРІРµРЅ вЂ” РїРµСЂРµР·Р°РїСѓСЃРєР°РµРј РµРіРѕ РґР»СЏ РїРµСЂРµСЃС‚СЂРѕР№РєРё С‚Р°Р±Р»РёС†С‹ РјР°СЂС€СЂСѓС‚РѕРІ (0.0.0.0/0 vs 10.200.0.0/24)
        if (NatBypassVpnService.isRunning) {
            val intent = Intent(context, NatBypassVpnService::class.java).apply {
                action = NatBypassVpnService.ACTION_RECONNECT
            }
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }

        viewModelScope.launch { refreshStatus() }
        return newTarget.isNotEmpty()
    }

    fun deletePeer(peerId: String) {
        MobileBridge.deletePeer(peerId)
        viewModelScope.launch { refreshStatus() }
    }


    fun setPeerNickname(peerId: String, nick: String) {
        prefs.edit().putString("nick_$peerId", nick).apply()
        viewModelScope.launch { refreshStatus() }
    }

    // в”Ђв”Ђ Profile actions в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

    fun switchProfile(profileId: String, context: Context) {
        if (MobileBridge.switchProfile(profileId)) {
            saveConfigToDisk(context)
            viewModelScope.launch { refreshStatus() }
        }
    }

    fun createProfile(
        context: Context, name: String, broker: String, topic: String, virtualIp: String,
        tgToken: String, tgChat: Long, tgProxy: String
    ) {
        val res = MobileBridge.createProfile(name, broker, topic, "", "", tgToken, tgChat, tgProxy, "dpi", true)
        if (virtualIp.isNotBlank()) {
            try {
                val json = JSONObject(res)
                val newId = json.optString("id", "")
                if (newId.isNotEmpty()) {
                    MobileBridge.setProfileVirtualIP(newId, virtualIp.trim())
                }
            } catch (_: Exception) {}
            MobileBridge.setVirtualIP(virtualIp.trim())
        }
        saveConfigToDisk(context)
        viewModelScope.launch { refreshStatus() }
    }

    fun updateProfile(
        context: Context, id: String, name: String, broker: String, topic: String, virtualIp: String,
        tgToken: String, tgChat: Long, tgProxy: String
    ) {
        MobileBridge.updateProfile(id, name, broker, topic, "", "", tgToken, tgChat, tgProxy, "dpi")
        if (virtualIp.isNotBlank()) {
            MobileBridge.setProfileVirtualIP(id, virtualIp.trim())
        }
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

    fun exportAllProfiles(): String = MobileBridge.exportAllProfilesJSON()

    fun importAllProfiles(context: Context, jsonStr: String): Boolean {
        val res = MobileBridge.importAllProfilesJSON(jsonStr)
        if (res == "OK") {
            saveConfigToDisk(context)
            viewModelScope.launch { refreshStatus() }
            return true
        }
        return false
    }

    fun setAWGPreset(preset: String) = MobileBridge.setAWGPreset(preset)

    fun setAWGCustom(jc: Int, jmin: Int, jmax: Int, s1: Int, s2: Int, h1: String, h2: String, h3: String, h4: String) {
        MobileBridge.setAWGCustom(jc, jmin, jmax, s1, s2, h1, h2, h3, h4)
    }


    fun clearPeers(context: Context) {
        MobileBridge.clearPeers()
        viewModelScope.launch { refreshStatus() }
    }

    fun syncNetwork() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                MobileBridge.refreshPublicIP()
            }
            delay(500)
            refreshStatus()
        }
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

