package org.natbypass.app.util

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

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

    private const val TAG = "AppUpdateManager"

    private val _updateState = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val updateState: StateFlow<UpdateState> = _updateState.asStateFlow()

    private var downloadCancelled = false
    private val isDownloading = AtomicBoolean(false)

    // High-speed CDN mirror proxies for GitHub releases in Russia & CIS
    private val PROXY_PREFIXES = listOf(
        "https://gh-proxy.com/",
        "https://ghproxy.net/",
        "https://ghfast.top/"
    )

    fun getDownloadMirrors(apkUrl: String): List<String> {
        val mirrors = mutableListOf<String>()
        if (apkUrl.contains("github.com/")) {
            for (prefix in PROXY_PREFIXES) {
                mirrors.add(prefix + apkUrl)
            }
        }
        mirrors.add(apkUrl) // Direct GitHub fallback
        return mirrors
    }

    suspend fun checkForUpdates(
        currentVersion: String,
        manual: Boolean,
        includePrerelease: Boolean = false
    ): UpdateState = withContext(Dispatchers.IO) {
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
                        best = obj
                        break
                    }
                    best ?: throw Exception("Нет доступных релизов на GitHub")
                } else {
                    JSONObject(response)
                }
                val tagName = releaseObj.optString("tag_name", "").removePrefix("v")
                val isPrerelease = releaseObj.optBoolean("prerelease", false)
                val releaseBody = if (releaseObj.isNull("body")) {
                    "Улучшена стабильность и производительность."
                } else {
                    releaseObj.optString("body", "").takeIf { it.isNotBlank() }
                        ?: "Улучшена стабильность и производительность."
                }

                data class ApkAsset(val name: String, val url: String, val size: Long)
                val apkAssets = mutableListOf<ApkAsset>()
                val assets = releaseObj.optJSONArray("assets")
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        val name = asset.optString("name", "")
                        if (name.endsWith(".apk", ignoreCase = true)) {
                            apkAssets.add(ApkAsset(
                                name = name,
                                url  = asset.optString("browser_download_url", ""),
                                size = asset.optLong("size", 0L)
                            ))
                        }
                    }
                }

                // Choose best APK matching device architecture from Build.SUPPORTED_ABIS
                var chosenApk: ApkAsset? = null
                val supportedAbis = Build.SUPPORTED_ABIS ?: emptyArray()
                for (abi in supportedAbis) {
                    val normalizedAbi = abi.lowercase()
                    chosenApk = apkAssets.firstOrNull { it.name.lowercase().contains(normalizedAbi) }
                    if (chosenApk != null) break
                }
                // Fallback: universal APK or first available APK
                if (chosenApk == null) {
                    chosenApk = apkAssets.firstOrNull { it.name.lowercase().contains("universal") }
                        ?: apkAssets.firstOrNull()
                }

                val apkDownloadUrl = chosenApk?.url ?: ""
                val apkSize = chosenApk?.size ?: 0L

                val isCurrentBeta = currentVersion.contains("beta", ignoreCase = true) ||
                    currentVersion.contains("rc", ignoreCase = true) ||
                    currentVersion.contains("-")
                val isRollback = !includePrerelease && isCurrentBeta && (tagName != currentVersion.removePrefix("v"))
                val isNewer = if (includePrerelease) {
                    tagName != currentVersion.removePrefix("v")
                } else {
                    isNewerVersion(currentVersion, tagName) || isRollback
                }

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
                    // Try fallback to mirror manifest
                    val manifestUrl = if (includePrerelease) {
                        "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest-beta.json"
                    } else {
                        "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest.json"
                    }
                    return@withContext checkFromMirrorManifest(manifestUrl, currentVersion, includePrerelease)
                }
            } else {
                // Non-200 from GitHub API -> Fallback to mirror manifest
                val manifestUrl = if (includePrerelease) {
                    "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest-beta.json"
                } else {
                    "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest.json"
                }
                return@withContext checkFromMirrorManifest(manifestUrl, currentVersion, includePrerelease)
            }
        } catch (e: Exception) {
            // Network error connecting to GitHub API -> Fallback to mirror manifest
            try {
                val manifestUrl = if (includePrerelease) {
                    "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest-beta.json"
                } else {
                    "https://gh-proxy.com/https://raw.githubusercontent.com/jamixm4-crypto/natbypass/main/mirror/releases/latest.json"
                }
                return@withContext checkFromMirrorManifest(manifestUrl, currentVersion, includePrerelease)
            } catch (_: Exception) {
                val err = UpdateState.Error(e.message ?: "Ошибка сети при проверке обновлений")
                _updateState.value = err
                return@withContext err
            }
        }
    }

    private fun checkFromMirrorManifest(
        manifestUrl: String,
        currentVersion: String,
        includePrerelease: Boolean
    ): UpdateState {
        val u = URL(manifestUrl)
        val conn = u.openConnection() as HttpURLConnection
        conn.connectTimeout = 8000
        conn.readTimeout = 8000
        conn.setRequestProperty("User-Agent", "NatBypass-Android-App")
        if (conn.responseCode != 200) {
            throw IOException("Mirror returned HTTP ${conn.responseCode}")
        }
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        val root = JSONObject(text)
        val version = root.optString("version", "").removePrefix("v")
        val isPrerelease = root.optBoolean("prerelease", false)
        val body = root.optString("release_notes", "Улучшена стабильность и производительность.")
        val assetsObj = root.optJSONObject("assets")

        var apkUrl = ""
        var apkSize = 0L

        if (assetsObj != null) {
            val supportedAbis = Build.SUPPORTED_ABIS ?: emptyArray()
            val isArm64 = supportedAbis.any { it.contains("arm64", ignoreCase = true) }
            val targetAsset = if (isArm64 && assetsObj.has("android/arm64")) {
                assetsObj.optJSONObject("android/arm64")
            } else {
                assetsObj.optJSONObject("android/universal") ?: assetsObj.optJSONObject("android/arm64")
            }

            if (targetAsset != null) {
                apkUrl = targetAsset.optString("url", "")
                apkSize = targetAsset.optLong("size", 0L)
            }
        }

        if (apkUrl.isNotBlank()) {
            val isNewer = if (includePrerelease) {
                version != currentVersion.removePrefix("v")
            } else {
                isNewerVersion(currentVersion, version)
            }
            val state = UpdateState.Available(
                version      = version,
                changelog    = body,
                apkUrl       = apkUrl,
                sizeBytes    = apkSize,
                isNewer      = isNewer,
                isPrerelease = isPrerelease,
                isRollback   = false
            )
            _updateState.value = state
            return state
        }
        throw IOException("APK asset not found in mirror manifest")
    }

    private data class StreamConnection(
        val connection: HttpURLConnection,
        val responseCode: Int,
        val finalUrl: String,
        val contentLength: Long,
        val isPartial: Boolean
    )

    private fun openStreamWithManualRedirects(
        initialUrl: String,
        startOffset: Long
    ): StreamConnection {
        var currentUrl = initialUrl
        var hops = 0
        val maxHops = 6

        while (hops < maxHops) {
            val u = URL(currentUrl)
            val conn = u.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false // Keep manual control so Range is never dropped on redirect!
            conn.connectTimeout = 15000
            conn.readTimeout = 20000 // Resilient socket timeout for mobile networks in Russia
            conn.setRequestProperty("User-Agent", "NatBypass-Android-App")
            conn.setRequestProperty("Accept-Encoding", "identity")
            conn.setRequestProperty("Connection", "keep-alive")
            if (startOffset > 0) {
                conn.setRequestProperty("Range", "bytes=$startOffset-")
            }

            val code = conn.responseCode
            if (code in 301..308) {
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                if (location.isNullOrBlank()) {
                    throw IOException("HTTP $code redirect without Location header from $currentUrl")
                }
                currentUrl = URL(u, location).toString()
                hops++
                continue
            }

            val isPartial = (code == 206)
            var cl = conn.contentLengthLong
            if (isPartial) {
                val cr = conn.getHeaderField("Content-Range")
                if (cr != null && cr.contains("/")) {
                    val totalStr = cr.substringAfter("/").trim()
                    val parsedTotal = totalStr.toLongOrNull()
                    if (parsedTotal != null && parsedTotal > 0) {
                        cl = parsedTotal
                    }
                }
            }

            return StreamConnection(conn, code, currentUrl, cl, isPartial)
        }
        throw IOException("Too many HTTP redirects ($hops) when connecting to $initialUrl")
    }

    suspend fun downloadAndInstall(
        context: Context,
        version: String,
        apkUrl: String,
        sizeBytes: Long
    ) = withContext(Dispatchers.IO) {
        if (!isDownloading.compareAndSet(false, true)) {
            return@withContext
        }
        downloadCancelled = false

        val estMB = if (sizeBytes > 0) sizeBytes.toFloat() / (1024 * 1024) else 25f
        _updateState.value = UpdateState.Downloading(
            version      = version,
            progress     = 0f,
            downloadedMB = 0f,
            totalMB      = estMB,
            speedMBs     = 0f,
            etaSec       = 0,
        )

        val destFile = File(context.cacheDir, "NatBypass-v$version.apk")
        val partFile = File(context.cacheDir, "NatBypass-v$version.apk.part")

        // If completed valid APK already exists in cache, launch immediately!
        if (destFile.exists() && isValidApk(destFile)) {
            _updateState.value = UpdateState.ReadyToInstall(destFile)
            launchInstaller(context, destFile)
            isDownloading.set(false)
            return@withContext
        }

        val mirrors = getDownloadMirrors(apkUrl)
        var mirrorIndex = 0
        var totalLength = sizeBytes
        var downloadedBytes = if (partFile.exists()) partFile.length() else 0L

        // If part file is larger than expected, reset
        if (totalLength > 0 && downloadedBytes > totalLength) {
            partFile.delete()
            downloadedBytes = 0L
        }

        val maxAttempts = mirrors.size * 4
        var attempts = 0
        var success = false

        val raf = RandomAccessFile(partFile, "rw")

        try {
            while (attempts < maxAttempts && !downloadCancelled) {
                if (totalLength > 0 && downloadedBytes >= totalLength) {
                    success = true
                    break
                }

                val targetUrl = mirrors[mirrorIndex % mirrors.size]
                Log.i(TAG, "Connecting to mirror [${mirrorIndex % mirrors.size}/${mirrors.size}]: $targetUrl (resume at $downloadedBytes)")

                var streamConn: StreamConnection? = null
                var input: InputStream? = null

                try {
                    streamConn = openStreamWithManualRedirects(targetUrl, downloadedBytes)
                    val code = streamConn.responseCode
                    if (code != 200 && code != 206) {
                        throw IOException("HTTP $code from $targetUrl")
                    }

                    if (totalLength <= 0 && streamConn.contentLength > 0) {
                        totalLength = if (streamConn.isPartial && downloadedBytes > 0) {
                            streamConn.contentLength
                        } else {
                            downloadedBytes + streamConn.contentLength
                        }
                    }

                    if (!streamConn.isPartial && downloadedBytes > 0) {
                        // Server ignored Range header and sent entire file from 0.
                        // Skip this mirror if we have already downloaded significant data to preserve progress!
                        if (downloadedBytes > 1024 * 1024 && attempts < maxAttempts - 2) {
                            Log.w(TAG, "Mirror $targetUrl ignored Range header, skipping to next mirror to preserve $downloadedBytes bytes")
                            streamConn.connection.disconnect()
                            mirrorIndex++
                            attempts++
                            continue
                        }
                        Log.w(TAG, "Server ignored Range request, resetting to offset 0")
                        downloadedBytes = 0L
                        raf.seek(0)
                        raf.setLength(0)
                    } else {
                        raf.seek(downloadedBytes)
                    }

                    input = BufferedInputStream(streamConn.connection.inputStream, 128 * 1024)
                    val buffer = ByteArray(128 * 1024)

                    var lastReadTime = System.currentTimeMillis()
                    var lastReportTime = System.currentTimeMillis()
                    var bytesSinceReport = 0L
                    var smoothedSpeed = 0f

                    // Active watchdog: detect stall if no data received for 20 seconds
                    val watchdogJob = launch(Dispatchers.IO) {
                        while (isActive && !downloadCancelled) {
                            delay(1000)
                            val elapsedSinceRead = System.currentTimeMillis() - lastReadTime
                            if (elapsedSinceRead > 20000) {
                                Log.w(TAG, "Stream stalled (>20s without data), aborting connection for failover")
                                try {
                                    streamConn.connection.disconnect()
                                } catch (_: Throwable) {}
                                break
                            }
                        }
                    }

                    try {
                        while (!downloadCancelled) {
                            val bytesRead = input.read(buffer)
                            if (bytesRead == -1) {
                                break // End of stream
                            }

                            raf.write(buffer, 0, bytesRead)
                            downloadedBytes += bytesRead
                            bytesSinceReport += bytesRead
                            val now = System.currentTimeMillis()
                            lastReadTime = now

                            val dt = now - lastReportTime
                            if (dt >= 200 || (totalLength > 0 && downloadedBytes >= totalLength)) {
                                val instSpeedMBs = (bytesSinceReport.toFloat() / (1024 * 1024)) / (dt / 1000f)
                                smoothedSpeed = if (smoothedSpeed == 0f) {
                                    instSpeedMBs
                                } else {
                                    smoothedSpeed * 0.7f + instSpeedMBs * 0.3f
                                }
                                bytesSinceReport = 0L
                                lastReportTime = now

                                val progress = if (totalLength > 0) {
                                    (downloadedBytes.toFloat() / totalLength).coerceIn(0f, 1f)
                                } else 0.5f

                                val totalMB = if (totalLength > 0) {
                                    totalLength.toFloat() / (1024 * 1024)
                                } else (downloadedBytes.toFloat() / (1024 * 1024))

                                val downloadedMB = downloadedBytes.toFloat() / (1024 * 1024)
                                val remainingBytes = if (totalLength > downloadedBytes) totalLength - downloadedBytes else 0L
                                val etaSec = if (smoothedSpeed > 0.02f) {
                                    (remainingBytes / (smoothedSpeed * 1024 * 1024)).toInt().coerceAtLeast(0)
                                } else 0

                                _updateState.value = UpdateState.Downloading(
                                    version      = version,
                                    progress     = progress,
                                    downloadedMB = downloadedMB,
                                    totalMB      = totalMB,
                                    speedMBs     = smoothedSpeed,
                                    etaSec       = etaSec,
                                )
                            }
                        }
                    } finally {
                        watchdogJob.cancel()
                    }

                    if (totalLength > 0 && downloadedBytes >= totalLength) {
                        success = true
                        break
                    }

                } catch (e: Exception) {
                    if (downloadCancelled) break
                    Log.w(TAG, "Mirror error on $targetUrl: ${e.message}, failing over to next mirror...")
                    mirrorIndex++
                    attempts++
                    delay(300)
                } finally {
                    try { input?.close() } catch (_: Throwable) {}
                    try { streamConn?.connection?.disconnect() } catch (_: Throwable) {}
                }
            }
        } finally {
            try { raf.close() } catch (_: Throwable) {}
        }

        if (downloadCancelled) {
            partFile.delete()
            _updateState.value = UpdateState.Idle
            isDownloading.set(false)
            return@withContext
        }

        if (success && partFile.exists() && partFile.length() > 500 * 1024) {
            if (destFile.exists()) destFile.delete()
            if (partFile.renameTo(destFile) && isValidApk(destFile)) {
                _updateState.value = UpdateState.ReadyToInstall(destFile)
                launchInstaller(context, destFile)
            } else {
                _updateState.value = UpdateState.Error("Файл APK повреждён или не прошёл проверку целостности")
            }
        } else {
            _updateState.value = UpdateState.Error("Не удалось загрузить обновление (превышено число попыток)")
        }
        isDownloading.set(false)
    }

    fun isValidApk(file: File): Boolean {
        if (!file.exists() || file.length() < 500 * 1024) return false
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val magic = ByteArray(4)
                raf.readFully(magic)
                // ZIP magic header 'PK\x03\x04'
                magic[0] == 0x50.toByte() && magic[1] == 0x4B.toByte() &&
                magic[2] == 0x03.toByte() && magic[3] == 0x04.toByte()
            }
        } catch (_: Throwable) {
            false
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
