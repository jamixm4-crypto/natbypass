package org.natbypass.app.util

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
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
    ) : UpdateState()
    data class Downloading(
        val version: String,
        val progress: Float, // 0.0 .. 1.0
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

    suspend fun checkForUpdates(currentVersion: String, manual: Boolean): UpdateState = withContext(Dispatchers.IO) {
        _updateState.value = UpdateState.Checking
        try {
            val url = URL("https://api.github.com/repos/jamixm4-crypto/natbypass/releases/latest")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("User-Agent", "NatBypass-Android-App")

            if (conn.responseCode == 200) {
                val response = conn.inputStream.bufferedReader().use { it.readText() }
                val releaseObj = JSONObject(response)
                val tagName = releaseObj.optString("tag_name", "").removePrefix("v")
                val releaseBody = releaseObj.optString("body", "Улучшена стабильность и производительность.")

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

                val isNewer = isNewerVersion(currentVersion, tagName)
                if (apkDownloadUrl.isNotEmpty()) {
                    val state = UpdateState.Available(
                        version    = tagName,
                        changelog  = releaseBody,
                        apkUrl     = apkDownloadUrl,
                        sizeBytes  = apkSize,
                        isNewer    = isNewer
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
        downloadCancelled = false
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
        }
    }

    fun cancelDownload() {
        downloadCancelled = true
        _updateState.value = UpdateState.Idle
    }

    fun dismiss() {
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
        try {
            val curParts = current.split(".").map { it.toIntOrNull() ?: 0 }
            val latParts = latest.split(".").map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(curParts.size, latParts.size)) {
                val c = curParts.getOrElse(i) { 0 }
                val l = latParts.getOrElse(i) { 0 }
                if (l > c) return true
                if (l < c) return false
            }
        } catch (_: Exception) {}
        return false
    }
}
