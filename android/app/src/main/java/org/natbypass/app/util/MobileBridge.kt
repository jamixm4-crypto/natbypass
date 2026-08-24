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
}
