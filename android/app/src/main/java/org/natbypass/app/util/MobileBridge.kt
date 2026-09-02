package org.natbypass.app.util

import java.lang.reflect.Method

object MobileBridge {

    private val mobileClass: Class<*>? by lazy {
        val candidates = listOf(
            "mobile.Mobile",
            "mobile.mobile.Mobile",
            "org.natbypass.mobile.Mobile"
        )
        var found: Class<*>? = null
        for (name in candidates) {
            try {
                found = Class.forName(name)
                if (found != null) break
            } catch (e: Throwable) {}
        }
        found
    }

    fun isAvailable(): Boolean = mobileClass != null

    fun getMethod(name: String): Method? {
        val clazz = mobileClass ?: return null
        return clazz.methods.firstOrNull { it.name.equals(name, ignoreCase = true) }
    }

    fun startEngine(configYaml: String, tunFd: Int): String {
        val method = getMethod("startEngine") ?: return "Go Mobile core not found"
        return try {
            if (method.parameterTypes.size == 2 && (method.parameterTypes[1] == Long::class.javaPrimitiveType || method.parameterTypes[1] == java.lang.Long::class.java)) {
                method.invoke(null, configYaml, tunFd.toLong()) as? String ?: "OK"
            } else {
                method.invoke(null, configYaml, tunFd) as? String ?: "OK"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    fun restartEngine(configYaml: String): String {
        val method = getMethod("restartEngine") ?: return startEngine(configYaml, 0)
        return try {
            method.invoke(null, configYaml) as? String ?: "OK"
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    fun stopEngine() {
        val method = getMethod("stopEngine") ?: return
        try {
            method.invoke(null)
        } catch (e: Exception) {}
    }

    fun detachTUN() {
        val method = getMethod("detachTUN") ?: return
        try {
            method.invoke(null)
        } catch (e: Exception) {}
    }

    fun setVirtualIP(vip: String) {
        val method = getMethod("setVirtualIP") ?: return
        try {
            method.invoke(null, vip)
        } catch (e: Exception) {}
    }

    fun getVirtualIP(): String {
        val method = getMethod("getVirtualIP") ?: return "100.64.200.10"
        return try {
            method.invoke(null) as? String ?: "100.64.200.10"
        } catch (e: Exception) {
            "100.64.200.10"
        }
    }

    fun getStatusJSON(): String {
        val method = getMethod("getStatusJSON") ?: return "{}"
        return try {
            method.invoke(null) as? String ?: "{}"
        } catch (e: Exception) {
            "{}"
        }
    }

    fun getPeersJSON(): String {
        val method = getMethod("getPeersJSON") ?: return "[]"
        return try {
            method.invoke(null) as? String ?: "[]"
        } catch (e: Exception) {
            "[]"
        }
    }

    fun getDiagnosticsJSON(): String {
        val method = getMethod("getDiagnosticsJSON") ?: return "{}"
        return try {
            method.invoke(null) as? String ?: "{}"
        } catch (e: Exception) {
            "{}"
        }
    }

    fun getLogsText(): String {
        val method = getMethod("getLogsText") ?: return "⚠️ Ядро GoMobile не загружено (библиотека mobile.aar)"
        return try {
            method.invoke(null) as? String ?: "Лог пуст."
        } catch (e: Exception) {
            "Ошибка чтения логов: ${e.message}"
        }
    }

    fun clearLogs() {
        val method = getMethod("clearLogs") ?: return
        try {
            method.invoke(null)
        } catch (e: Exception) {}
    }

    fun clearPeers() {
        val method = getMethod("clearPeers") ?: return
        try {
            method.invoke(null)
        } catch (e: Exception) {}
    }

    fun selectExitNode(deviceId: String) {
        val method = getMethod("selectExitNode") ?: return
        try {
            method.invoke(null, deviceId)
        } catch (e: Exception) {}
    }

    fun setAWGPreset(preset: String) {
        val method = getMethod("setAWGPreset") ?: return
        try {
            method.invoke(null, preset)
        } catch (e: Exception) {}
    }

    fun testTelegram(token: String, chat: String, proxy: String): String {
        val method = getMethod("testTelegram") ?: return ""
        return try {
            method.invoke(null, token, chat, proxy) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun testMQTT(broker: String, topic: String, user: String, pass: String): String {
        val method = getMethod("testMQTT") ?: return ""
        return try {
            method.invoke(null, broker, topic, user, pass) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun getProfilesJSON(): String {
        val method = getMethod("getProfilesJSON") ?: return "{}"
        return try {
            method.invoke(null) as? String ?: "{}"
        } catch (e: Exception) {
            "{}"
        }
    }

    fun createProfile(name: String, broker: String, topic: String, user: String, pass: String, tgToken: String, tgChat: Long, tgProxy: String, awgPreset: String, autoSwitch: Boolean): String {
        val method = getMethod("createProfile") ?: return ""
        return try {
            method.invoke(null, name, broker, topic, user, pass, tgToken, tgChat, tgProxy, awgPreset, autoSwitch) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun updateProfile(profileId: String, name: String, broker: String, topic: String, user: String, pass: String, tgToken: String, tgChat: Long, tgProxy: String, awgPreset: String): String {
        val method = getMethod("updateProfile") ?: return ""
        return try {
            method.invoke(null, profileId, name, broker, topic, user, pass, tgToken, tgChat, tgProxy, awgPreset) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun getConfigYAML(): String {
        val method = getMethod("getConfigYAML") ?: return "{}"
        return try {
            method.invoke(null) as? String ?: "{}"
        } catch (e: Exception) {
            "{}"
        }
    }

    fun switchProfile(profileId: String): Boolean {
        val method = getMethod("switchProfile") ?: return false
        return try {
            method.invoke(null, profileId) as? Boolean ?: false
        } catch (e: Exception) {
            false
        }
    }

    fun deleteProfile(profileId: String): Boolean {
        val method = getMethod("deleteProfile") ?: return false
        return try {
            method.invoke(null, profileId) as? Boolean ?: false
        } catch (e: Exception) {
            false
        }
    }

    fun exportProfileURI(profileId: String): String {
        val method = getMethod("exportProfileURI") ?: return ""
        return try {
            method.invoke(null, profileId) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun importProfileURI(rawUri: String): String {
        val method = getMethod("importProfileURI") ?: return ""
        return try {
            method.invoke(null, rawUri) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun pingPeer(deviceId: String): Long {
        val method = getMethod("pingPeer") ?: return -1L
        return try {
            val res = method.invoke(null, deviceId)
            when (res) {
                is Long -> res
                is Int -> res.toLong()
                else -> -1L
            }
        } catch (e: Exception) {
            -1L
        }
    }

    fun refreshPublicIP() {
        val method = getMethod("refreshPublicIP") ?: return
        try {
            method.invoke(null)
        } catch (e: Exception) {}
    }

    fun setAllowExitNode(allow: Boolean) {
        val method = getMethod("setAllowExitNode") ?: return
        try {
            method.invoke(null, allow)
        } catch (e: Exception) {}
    }

    fun getAllowExitNode(): Boolean {
        val method = getMethod("getAllowExitNode") ?: return false
        return try {
            method.invoke(null) as? Boolean ?: false
        } catch (e: Exception) {
            false
        }
    }

    fun setAdvertisedRoutes(routes: String) {
        val method = getMethod("setAdvertisedRoutes") ?: return
        try {
            method.invoke(null, routes)
        } catch (e: Exception) {}
    }

    fun getAdvertisedRoutes(): String {
        val method = getMethod("getAdvertisedRoutes") ?: return ""
        return try {
            method.invoke(null) as? String ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    fun setProfileVirtualIP(profileId: String, vip: String): Boolean {
        val method = getMethod("setProfileVirtualIP") ?: return false
        return try {
            method.invoke(null, profileId, vip) as? Boolean ?: false
        } catch (e: Exception) {
            false
        }
    }

    fun getLocalSubnetsJSON(): String {
        val method = getMethod("getLocalSubnetsJSON") ?: return "[]"
        return try {
            method.invoke(null) as? String ?: "[]"
        } catch (e: Exception) {
            "[]"
        }
    }

    /** Удалить конкретный узел из реестра (не удаляет все) */
    fun deletePeer(deviceId: String) {
        val method = getMethod("deletePeer") ?: return
        try {
            method.invoke(null, deviceId)
        } catch (e: Exception) {}
    }

    /** Получить статистику трафика: {"tx_bytes":…,"rx_bytes":…,"tx_speed_bps":…,"rx_speed_bps":…} */
    fun getTrafficStats(): String {
        val method = getMethod("getTrafficStats") ?: return "{}"
        return try {
            method.invoke(null) as? String ?: "{}"
        } catch (e: Exception) {
            "{}"
        }
    }

    /** Установить кастомные параметры AmneziaWG (Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4) */
    fun setAWGCustom(jc: Int, jmin: Int, jmax: Int, s1: Int, s2: Int, h1: String, h2: String, h3: String, h4: String) {
        val method = getMethod("setAWGCustom") ?: return
        try {
            method.invoke(null, jc, jmin, jmax, s1, s2, h1, h2, h3, h4)
        } catch (e: Exception) {}
    }

    /** Экспорт всех профилей в JSON */
    fun exportAllProfilesJSON(): String {
        val method = getMethod("exportAllProfilesJSON") ?: return "[]"
        return try {
            method.invoke(null) as? String ?: "[]"
        } catch (e: Exception) {
            "[]"
        }
    }

    /** Импорт профилей из JSON */
    fun importAllProfilesJSON(jsonStr: String): String {
        val method = getMethod("importAllProfilesJSON") ?: return "OK"
        return try {
            method.invoke(null, jsonStr) as? String ?: "OK"
        } catch (e: Exception) {
            "Ошибка: ${e.message}"
        }
    }
}




