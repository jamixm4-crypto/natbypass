package org.natbypass.app.ui.compose

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.natbypass.app.util.MobileBridge

// ── Data models ────────────────────────────────────────────────────────────────

data class DiagItem(
    val key: String,
    val label: String,
    val ok: Boolean,
    val detail: String,
    val extra: String = "",
)

/** Причина, по которой пир работает через Relay */
enum class RelayReason {
    SAME_PUBLIC_IP,      // Hairpin / same Wi-Fi
    HIGH_PROBE_COUNT,    // TSPU / firewall drops UDP
    SYMMETRIC_NAT,       // Symmetric NAT on peer side
    AWG_MISMATCH,        // AmneziaWG params mismatch
    VERSION_MISMATCH,    // Different binary version
    OK_DIRECT,           // Direct P2P established
    UNKNOWN,
}

data class PeerDiagItem(
    val deviceName: String,
    val virtualIP: String,
    val publicIP: String,
    val natType: String,
    val directP2P: Boolean,
    val activeEndpoint: String,
    val pingMs: Long,
    val probeCount: Int,
    val version: String,
    val awgH1: String,
    val awgMismatch: Boolean,
    val reasons: List<RelayReason>,
)

// ── Helper: parse peers from JSON and diagnose ─────────────────────────────────

private fun parsePeerDiags(peersJson: String, myPubIP: String, myVersion: String, myAwgActive: Boolean, myH1: String): List<PeerDiagItem> {
    return try {
        val arr = JSONArray(peersJson)
        (0 until arr.length()).mapNotNull { i ->
            try {
                val p = arr.getJSONObject(i)
                val vip = p.optString("virtual_ip", "")
                if (vip.isEmpty()) return@mapNotNull null

                val name        = p.optString("device_name", "").ifEmpty { p.optString("device_id", "?") }
                val pubIP       = p.optString("public_ip", "")
                val nat         = p.optString("nat_type", "")
                val direct      = p.optBoolean("direct_p2p", false)
                val ep          = p.optString("active_endpoint", "")
                val ping        = p.optLong("ping_ms", 0L)
                val probes      = p.optInt("probe_count", 0)
                val ver         = p.optString("version", "")
                val awgMismatch = p.optBoolean("awg_mismatch", false)
                val awgObj      = p.optJSONObject("awg")
                val peerH1      = awgObj?.optString("h1", "") ?: ""

                val reasons = mutableListOf<RelayReason>()
                if (direct) {
                    reasons += RelayReason.OK_DIRECT
                } else {
                    if (pubIP.isNotEmpty() && pubIP == myPubIP)
                        reasons += RelayReason.SAME_PUBLIC_IP
                    if (probes > 15)
                        reasons += RelayReason.HIGH_PROBE_COUNT
                    if (nat.contains("symmetric", ignoreCase = true))
                        reasons += RelayReason.SYMMETRIC_NAT
                    // awg_mismatch is set server-side (authoritative).
                    if (awgMismatch) {
                        reasons += RelayReason.AWG_MISMATCH
                    } else if (myH1.isNotEmpty() && peerH1.isNotEmpty() && myH1 != peerH1) {
                        reasons += RelayReason.AWG_MISMATCH
                    } else if (peerH1.isNotEmpty() && !myAwgActive) {
                        reasons += RelayReason.AWG_MISMATCH
                    } else if (peerH1.isEmpty() && myAwgActive) {
                        reasons += RelayReason.AWG_MISMATCH
                    }
                    val cleanPeerVer = ver.removePrefix("v")
                    val cleanMyVer   = myVersion.removePrefix("v")
                    if (cleanPeerVer.isNotEmpty() && cleanMyVer.isNotEmpty() && cleanPeerVer != cleanMyVer)
                        reasons += RelayReason.VERSION_MISMATCH
                    if (reasons.isEmpty())
                        reasons += RelayReason.UNKNOWN
                }

                PeerDiagItem(name, vip, pubIP, nat, direct, ep, ping, probes, ver, peerH1, awgMismatch, reasons)
            } catch (_: Exception) { null }
        }
    } catch (_: Exception) { emptyList() }
}

// ── Main screen ────────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var diagItems    by remember { mutableStateOf<List<DiagItem>>(emptyList()) }
    var peerDiags    by remember { mutableStateOf<List<PeerDiagItem>>(emptyList()) }
    var logsText     by remember { mutableStateOf("") }
    var rttHistory   by remember { mutableStateOf<List<Float>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun loadOnce(forceRefresh: Boolean = false) {
        isRefreshing = true
        withContext(Dispatchers.IO) {
            try {
                if (forceRefresh) {
                    MobileBridge.refreshPublicIP()
                    delay(400)
                }
                // Basic diagnostics
                val jsonStr = MobileBridge.getDiagnosticsJSON()
                val obj = JSONObject(jsonStr)
                val keys = listOf(
                    "internet"  to "Интернет",
                    "public_ip" to "Публичный IP",
                    "stun"      to "STUN-эндпоинт (NAT)",
                    "channel"   to "Активный канал",
                    "peers"     to "Узлы в сети",
                    "nat_type"  to "Тип NAT",
                )
                val parsed = keys.mapNotNull { (key, label) ->
                    val item = obj.optJSONObject(key) ?: return@mapNotNull null
                    DiagItem(key, label, item.optBoolean("ok", false), item.optString("detail",""), item.optString("extra",""))
                }

                // Status for peer analysis context
                val statusStr = MobileBridge.getStatusJSON()
                val statusObj = runCatching { JSONObject(statusStr) }.getOrNull() ?: JSONObject()
                val myPubIP   = statusObj.optString("public_ip", "")
                val myVersion = statusObj.optString("version", "")
                val myAwgActive = statusObj.optBoolean("awg_active", false) ||
                                  statusObj.optString("awg_version", "").isNotEmpty() ||
                                  statusObj.optString("awg_preset", "").isNotEmpty() ||
                                  statusObj.has("awg")
                val myH1 = statusObj.optJSONObject("awg")?.optString("h1", "") ?: ""

                // Peer relay analysis
                val peersStr = MobileBridge.getPeersJSON()
                val peers = parsePeerDiags(peersStr, myPubIP, myVersion, myAwgActive, myH1)

                val logs = MobileBridge.getLogsText()
                diagItems = parsed
                peerDiags = peers
                logsText  = logs
            } catch (_: Exception) {}
        }
        isRefreshing = false
    }

    fun buildFullReport(): String {
        val sb = StringBuilder()
        sb.append("=== ДИАГНОСТИКА NATBYPASS (Android) ===\n\n")
        sb.append("Базовые проверки:\n")
        diagItems.forEach { item ->
            val mark = if (item.ok) "[OK]" else "[!!]"
            sb.append("$mark ${item.label}: ${item.detail}")
            if (item.extra.isNotEmpty()) sb.append(" (${item.extra})")
            sb.append("\n")
        }
        if (peerDiags.isNotEmpty()) {
            sb.append("\nМатрица пиров:\n")
            peerDiags.forEach { p ->
                val st = if (p.directP2P) "P2P (${p.pingMs}ms)" else "Relay (${p.probeCount} probes)"
                sb.append("  ${p.deviceName} (${p.virtualIP}): $st\n")
                if (!p.directP2P) p.reasons.forEach { r -> sb.append("    -> ${r.toRussian()}\n") }
            }
        }
        sb.append("\n=== ЖУРНАЛ ЯДРА ===\n")
        sb.append(logsText.ifEmpty { "(логи пусты)" })
        return sb.toString()
    }

    fun copyToClipboard() {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("NatBypass Diagnostics", buildFullReport()))
        Toast.makeText(context, "Отчет скопирован в буфер!", Toast.LENGTH_SHORT).show()
    }

    fun shareReport() {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "NatBypass Диагностика и логи")
            putExtra(Intent.EXTRA_TEXT, buildFullReport())
        }
        context.startActivity(Intent.createChooser(sendIntent, "Поделиться диагностикой"))
    }

    LaunchedEffect(Unit) {
        loadOnce()
        while (true) {
            delay(3000)
            withContext(Dispatchers.IO) {
                try {
                    val arr = JSONArray(MobileBridge.getPeersJSON())
                    var total = 0L; var cnt = 0
                    for (i in 0 until arr.length()) {
                        val ms = arr.getJSONObject(i).optLong("ping_ms", 0L)
                        if (ms > 0) { total += ms; cnt++ }
                    }
                    val avg = if (cnt > 0) (total / cnt).toFloat() else 0f
                    rttHistory = (rttHistory + avg).takeLast(60)
                } catch (_: Exception) {}
            }
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Диагностика", fontWeight = FontWeight.Bold) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, "Назад") } },
                actions = {
                    IconButton(onClick = ::copyToClipboard) { Icon(Icons.Outlined.ContentCopy, "Скопировать") }
                    IconButton(onClick = ::shareReport)     { Icon(Icons.Outlined.Share, "Поделиться") }
                    if (isRefreshing) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp).padding(end = 8.dp), strokeWidth = 2.dp)
                    } else {
                        IconButton(onClick = { scope.launch { loadOnce(forceRefresh = true) } }) {
                            Icon(Icons.Outlined.Refresh, "Обновить")
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        }
    ) { pad ->
        Column(
            modifier = Modifier.padding(pad).fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            // Section: network checks
            SectionTitle("Сетевая диагностика")
            diagItems.forEach { DiagRow(it) }
            if (diagItems.isEmpty() && !isRefreshing)
                Text("Нет данных", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 8.dp))

            Spacer(Modifier.height(16.dp))

            // Section: RTT chart
            SectionTitle("История RTT")
            Spacer(Modifier.height(8.dp))
            RttChart(values = rttHistory, modifier = Modifier.fillMaxWidth().height(130.dp))

            Spacer(Modifier.height(16.dp))

            // Section: peer relay matrix
            if (peerDiags.isNotEmpty()) {
                SectionTitle("Матрица подключения пиров")
                Spacer(Modifier.height(4.dp))
                peerDiags.forEach { PeerDiagCard(it) }
                Spacer(Modifier.height(16.dp))
            }

            // Section: logs
            var logSearch by remember { mutableStateOf("") }
            var selectedLogLevel by remember { mutableStateOf("ALL") }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                SectionTitle("Журнал ядра")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AssistChip(onClick = { MobileBridge.clearLogs(); logsText = ""; Toast.makeText(context, "Журнал очищен", Toast.LENGTH_SHORT).show() },
                        label = { Text("Очистить", fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Outlined.DeleteOutline, null, modifier = Modifier.size(14.dp)) })
                    AssistChip(onClick = ::copyToClipboard,
                        label = { Text("Копировать", fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Outlined.ContentCopy, null, modifier = Modifier.size(14.dp)) })
                }
            }

            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = logSearch, onValueChange = { logSearch = it },
                placeholder = { Text("Поиск в логах...") },
                leadingIcon = { Icon(Icons.Outlined.Search, null, modifier = Modifier.size(18.dp)) },
                trailingIcon = { if (logSearch.isNotEmpty()) IconButton(onClick = { logSearch = "" }) { Icon(Icons.Outlined.Close, null, modifier = Modifier.size(16.dp)) } },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("ALL" to "Все", "ERROR" to "Ошибки", "WARN" to "Предупр.", "INFO" to "Инфо").forEach { (lvl, label) ->
                    FilterChip(selected = selectedLogLevel == lvl, onClick = { selectedLogLevel = lvl }, label = { Text(label, fontSize = 11.sp) })
                }
            }

            Spacer(Modifier.height(8.dp))
            val filteredLogs = remember(logsText, logSearch, selectedLogLevel) {
                if (logsText.isEmpty()) return@remember "Логи пусты"
                val matched = logsText.lines().filter { line ->
                    (logSearch.isBlank() || line.contains(logSearch, ignoreCase = true)) &&
                    when (selectedLogLevel) {
                        "ERROR" -> line.contains("ERROR", true) || line.contains("ERR", true)
                        "WARN"  -> line.contains("WARN", true)
                        "INFO"  -> line.contains("INFO", true)
                        else    -> true
                    }
                }
                if (matched.isEmpty()) "Ничего не найдено" else matched.joinToString("\n")
            }

            Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f), modifier = Modifier.fillMaxWidth()) {
                Text(text = filteredLogs,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 16.sp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(12.dp))
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

// ── Peer card ──────────────────────────────────────────────────────────────────

@Composable
private fun PeerDiagCard(peer: PeerDiagItem) {
    Surface(
        shape  = RoundedCornerShape(12.dp),
        color  = if (peer.directP2P)
            MaterialTheme.natColors.success.copy(alpha = 0.08f)
        else
            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.25f),
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (peer.directP2P) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                    contentDescription = null,
                    tint = if (peer.directP2P) MaterialTheme.natColors.success else MaterialTheme.natColors.warning,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(peer.deviceName, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                    Text(peer.virtualIP, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (peer.natType.isNotEmpty()) {
                    Surface(shape = RoundedCornerShape(6.dp), color = MaterialTheme.colorScheme.secondaryContainer) {
                        Text(peer.natType.take(14), style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                    }
                }
            }

            Spacer(Modifier.height(4.dp))

            val connInfo = if (peer.directP2P)
                "P2P  •  ${peer.activeEndpoint}  •  ${peer.pingMs} мс"
            else
                "Relay  •  ${peer.probeCount} проб UDP"
            Text(connInfo, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            if (!peer.directP2P && peer.reasons.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                peer.reasons.forEach { reason ->
                    Text(
                        text  = "⚠ ${reason.toRussian()}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(vertical = 1.dp),
                    )
                }
            }

            if (peer.version.isNotEmpty()) {
                Spacer(Modifier.height(2.dp))
                Text("Версия: ${peer.version}", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f))
            }
        }
    }
}

// ── Reason localisation ────────────────────────────────────────────────────────

private fun RelayReason.toRussian(): String = when (this) {
    RelayReason.SAME_PUBLIC_IP   -> "[Hairpin] Одинаковый внешний IP — проверьте AP Isolation на роутере"
    RelayReason.HIGH_PROBE_COUNT -> "[ТСПУ/DPI] UDP-пробы блокируются — AWG 3.1 strict должен быть активен с обеих сторон"
    RelayReason.SYMMETRIC_NAT    -> "[Symmetric NAT] Порты непредсказуемы — запущен wide-sweep и TCP fallback"
    RelayReason.AWG_MISMATCH     -> "[AWG] Параметры AmneziaWG (H1..H4 / S1..S2 / Jc) не совпадают у обоих узлов!"
    RelayReason.VERSION_MISMATCH -> "[Версия] Пир на другом билде — рекомендуется обновить все узлы"
    RelayReason.OK_DIRECT        -> "Прямое P2P соединение установлено"
    RelayReason.UNKNOWN          -> "[Unknown] Сигнал доходит, но UDP ответы не возвращаются"
}

// ── Shared composables ─────────────────────────────────────────────────────────

@Composable
private fun SectionTitle(text: String) {
    Text(text = text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(bottom = 2.dp))
}

@Composable
private fun DiagRow(item: DiagItem) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.Top) {
        Icon(
            imageVector = if (item.ok) Icons.Filled.CheckCircle else Icons.Filled.Warning,
            contentDescription = null,
            tint = if (item.ok) MaterialTheme.natColors.success else MaterialTheme.natColors.warning,
            modifier = Modifier.size(20.dp).padding(top = 2.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column {
            Text(item.label, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodyMedium)
            Text(
                text  = if (item.extra.isEmpty()) item.detail else "${item.detail} (${item.extra})",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun RttChart(values: List<Float>, modifier: Modifier = Modifier) {
    val primaryColor = MaterialTheme.colorScheme.primary
    val surfaceColor = MaterialTheme.colorScheme.surfaceVariant
    Surface(modifier = modifier, shape = RoundedCornerShape(16.dp), color = surfaceColor.copy(alpha = 0.5f)) {
        if (values.size < 2) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                Text("Недостаточно данных", style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f))
            }
        } else {
            Canvas(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                val maxVal = values.maxOrNull()?.takeIf { it > 0 } ?: 1f
                val w = size.width; val h = size.height; val step = w / (values.size - 1)
                val path = Path()
                values.forEachIndexed { i, v ->
                    val x = i * step; val y = h - (v / maxVal) * h
                    if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
                }
                drawPath(path, primaryColor, style = Stroke(3.dp.toPx(), cap = StrokeCap.Round))
                values.forEachIndexed { i, v ->
                    drawCircle(primaryColor, 4.dp.toPx(), Offset(i * step, h - (v / maxVal) * h))
                }
            }
        }
    }
}
