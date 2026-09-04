package org.natbypass.app.util

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

sealed class UpdateState {
    object Idle : UpdateState()
    object Checking : UpdateState()
    data class Available(
        val version: String,
        val changelog: String,
        val apkUrl: String,
        val sizeBytes: Long,
        val isNewer: Boolean,
        val isPrerelease: Boolean = false,
        val isRollback: Boolean = false,
    ) : UpdateState()
    data class Downloading(
        val version: String,
        val progress: Float,
        val downloadedMB: Float,
        val totalMB: Float,
        val speedMBs: Float,
        val etaSec: Int,
    ) : UpdateState()
    data class ReadyToInstall(val apkFile: File) : UpdateState()
    data class Error(val message: String) : UpdateState()
}

object AppUpdateManager {

    private val _updateState = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val updateState: StateFlow<UpdateState> = _updateState.asStateFlow()

    private var downloadCancelled = false
    private val isDownloading = java.util.concurrent.atomic.AtomicBoolean(false)

    suspend fun checkForUpdates(currentVersion: String, manual: Boolean, includePrerelease: Boolean = false): UpdateState = withContext(Dispatchers.IO) {
        _updateState.value = UpdateState.Checking
        try {
            val apiUrl = if (includePrerelease) {
                "https://api.github.com/repos/jamixm4-crypto/natbypass/releases?per_page=10"
            } else {
                "https://api.github.com/repos/jamixm4-crypto/natbypass/releases/latest"
            }
            val url = URL(apiUrl)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("User-Agent", "NatBypass-Android-App")

            if (conn.responseCode == 200) {
                val response = conn.inputStream.bufferedReader().use { it.readText() }
                val releaseObj: JSONObject = if (includePrerelease) {
                    val arr = JSONArray(response)
                    var best: JSONObject? = null
                    for (i in 0 until arr.length()) {
                        val obj = arr.getJSONObject(i)
                        if (obj.optBoolean("draft", false)) continue
                        if (best == null || compareSemVer(obj.optString("tag_name", ""), best.optString("tag_name", "")) > 0) {
                            best = obj
                        }
                    }
                    best ?: throw Exception("Нет доступных релизов на GitHub")
                } else {
                    JSONObject(response)
                }
                val tagName = releaseObj.optString("tag_name", "").removePrefix("v")
                val isPrerelease = releaseObj.optBoolean("prerelease", false)
                // GitHub API может прислать "body": null (JSON null), в этом случае
                // optString вернёт строку "null" — проверяем явно через isNull()
                val releaseBody = if (releaseObj.isNull("body")) {
                    "Улучшена стабильность и производительность."
                } else {
                    releaseObj.optString("body", "").takeIf { it.isNotBlank() }
                        ?: "Улучшена стабильность и производительность."
                }

                var apkDownloadUrl = ""
                var apkSize = 0L
                val assets = releaseObj.optJSONArray("assets")
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        val name = asset.optString("name", "")
                        if (name.endsWith(".apk", ignoreCase = true)) {
                            apkDownloadUrl = asset.optString("browser_download_url", "")
                            apkSize = asset.optLong("size", 0L)
                            break
                        }
                    }
                }

                val isCurrentBeta = currentVersion.contains("beta", ignoreCase = true) ||
                    currentVersion.contains("rc", ignoreCase = true) ||
                    currentVersion.contains("-")
                val isRollback = !includePrerelease && isCurrentBeta && (tagName != currentVersion.removePrefix("v"))
                val isNewer = isNewerVersion(currentVersion, tagName) || isRollback

                if (apkDownloadUrl.isNotEmpty()) {
                    val state = UpdateState.Available(
                        version      = tagName,
                        changelog    = releaseBody,
                        apkUrl       = apkDownloadUrl,
                        sizeBytes    = apkSize,
                        isNewer      = isNewer,
                        isPrerelease = isPrerelease,
                        isRollback   = isRollback
                    )
                    _updateState.value = state
                    return@withContext state
                } else {
                    val err = UpdateState.Error("APK файл не найден в релизе v$tagName")
                    _updateState.value = err
                    return@withContext err
                }
            } else {
                val err = UpdateState.Error("Сервер вернул код ${conn.responseCode}")
                _updateState.value = err
                return@withContext err
            }
        } catch (e: Exception) {
            val err = UpdateState.Error(e.message ?: "Ошибка сети при проверке обновлений")
            _updateState.value = err
            return@withContext err
        }
    }

    suspend fun downloadAndInstall(context: Context, version: String, apkUrl: String, sizeBytes: Long) = withContext(Dispatchers.IO) {
        if (!isDownloading.compareAndSet(false, true)) {
            return@withContext
        }
        downloadCancelled = false

        val estMB = if (sizeBytes > 0) sizeBytes.toFloat() / (1024 * 1024) else 15f
        _updateState.value = UpdateState.Downloading(
            version      = version,
            progress     = 0f,
            downloadedMB = 0f,
            totalMB      = estMB,
            speedMBs     = 0f,
            etaSec       = 0,
        )

        val destFile = File(context.cacheDir, "NatBypass-v$version.apk")
        if (destFile.exists()) destFile.delete()

        try {
            val url = URL(apkUrl)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 15000
            conn.readTimeout = 30000
            conn.setRequestProperty("User-Agent", "NatBypass-Android-App")

            val totalLength = if (sizeBytes > 0) sizeBytes else conn.contentLengthLong.takeIf { it > 0 } ?: (15 * 1024 * 1024L)
            val totalMB = (totalLength.toFloat() / (1024 * 1024))

            conn.inputStream.use { input ->
                FileOutputStream(destFile).use { output ->
                    val buffer = ByteArray(32 * 1024)
                    var bytesRead: Int
                    var totalRead = 0L
                    var startTime = System.currentTimeMillis()
                    var lastUpdate = System.currentTimeMillis()
                    var bytesInWindow = 0L

                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        if (downloadCancelled) {
                            destFile.delete()
                            _updateState.value = UpdateState.Idle
                            return@withContext
                        }
                        output.write(buffer, 0, bytesRead)
                        totalRead += bytesRead
                        bytesInWindow += bytesRead

                        val now = System.currentTimeMillis()
                        val dt = now - lastUpdate
                        if (dt >= 200 || totalRead == totalLength) {
                            val elapsedSec = (now - startTime) / 1000f
                            val speedMBs = if (elapsedSec > 0.1f) {
                                (totalRead.toFloat() / (1024 * 1024)) / elapsedSec
                            } else 0f

                            val downloadedMB = totalRead.toFloat() / (1024 * 1024)
                            val progress = (totalRead.toFloat() / totalLength).coerceIn(0f, 1f)

                            val remainingBytes = totalLength - totalRead
                            val etaSec = if (speedMBs > 0.01f) {
                                (remainingBytes / (speedMBs * 1024 * 1024)).toInt().coerceAtLeast(0)
                            } else 0

                            _updateState.value = UpdateState.Downloading(
                                version      = version,
                                progress     = progress,
                                downloadedMB = downloadedMB,
                                totalMB      = totalMB,
                                speedMBs     = speedMBs,
                                etaSec       = etaSec,
                            )
                            lastUpdate = now
                            bytesInWindow = 0
                        }
                    }
                }
            }

            _updateState.value = UpdateState.ReadyToInstall(destFile)
            launchInstaller(context, destFile)

        } catch (e: Exception) {
            _updateState.value = UpdateState.Error("Ошибка загрузки: ${e.message}")
        } finally {
            isDownloading.set(false)
        }
    }

    fun cancelDownload() {
        downloadCancelled = true
        isDownloading.set(false)
        _updateState.value = UpdateState.Idle
    }

    fun dismiss() {
        downloadCancelled = true
        isDownloading.set(false)
        _updateState.value = UpdateState.Idle
    }

    fun launchInstaller(context: Context, apkFile: File) {
        try {
            val apkUri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.provider",
                apkFile
            )
            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(apkUri, "application/vnd.android.package-archive")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
            }
            context.startActivity(installIntent)
        } catch (e: Exception) {
            _updateState.value = UpdateState.Error("Не удалось запустить установщик: ${e.message}")
        }
    }

    private fun isNewerVersion(current: String, latest: String): Boolean {
        return compareSemVer(latest, current) > 0
    }

    fun compareSemVer(v1Raw: String, v2Raw: String): Int {
        try {
            val v1Clean = v1Raw.trim().removePrefix("v").removePrefix("V")
            val v2Clean = v2Raw.trim().removePrefix("v").removePrefix("V")

            val v1Parts = v1Clean.split("-", limit = 2)
            val v2Parts = v2Clean.split("-", limit = 2)

            val v1Main = v1Parts[0].split(".").map { it.toIntOrNull() ?: 0 }
            val v2Main = v2Parts[0].split(".").map { it.toIntOrNull() ?: 0 }

            val maxLen = maxOf(v1Main.size, v2Main.size)
            for (i in 0 until maxLen) {
                val p1 = v1Main.getOrElse(i) { 0 }
                val p2 = v2Main.getOrElse(i) { 0 }
                if (p1 > p2) return 1
                if (p1 < p2) return -1
            }

            val v1HasPre = v1Parts.size > 1 && v1Parts[1].isNotBlank()
            val v2HasPre = v2Parts.size > 1 && v2Parts[1].isNotBlank()

            if (!v1HasPre && v2HasPre) return 1
            if (v1HasPre && !v2HasPre) return -1
            if (!v1HasPre && !v2HasPre) return 0

            return comparePrerelease(v1Parts[1], v2Parts[1])
        } catch (_: Exception) {
            return 0
        }
    }

    private fun comparePrerelease(pre1: String, pre2: String): Int {
        val parts1 = pre1.split(".")
        val parts2 = pre2.split(".")
        val minLen = minOf(parts1.size, parts2.size)

        for (i in 0 until minLen) {
            val id1 = parts1[i]
            val id2 = parts2[i]

            val num1 = id1.toLongOrNull()
            val num2 = id2.toLongOrNull()

            if (num1 != null && num2 != null) {
                if (num1 > num2) return 1
                if (num1 < num2) return -1
            } else if (num1 != null && num2 == null) {
                return -1
            } else if (num1 == null && num2 != null) {
                return 1
            } else {
                val cmp = id1.compareTo(id2)
                if (cmp != 0) return if (cmp > 0) 1 else -1
            }
        }

        if (parts1.size > parts2.size) return 1
        if (parts1.size < parts2.size) return -1
        return 0
    }
}
