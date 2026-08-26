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
import org.json.JSONObject
import org.natbypass.app.util.MobileBridge

data class DiagItem(
    val key: String,
    val label: String,
    val ok: Boolean,
    val detail: String,
    val extra: String = "",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var diagItems   by remember { mutableStateOf<List<DiagItem>>(emptyList()) }
    var logsText    by remember { mutableStateOf("") }
    var rttHistory  by remember { mutableStateOf<List<Float>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun loadOnce() {
        isRefreshing = true
        withContext(Dispatchers.IO) {
            try {
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
                    DiagItem(
                        key    = key,
                        label  = label,
                        ok     = item.optBoolean("ok", false),
                        detail = item.optString("detail", ""),
                        extra  = item.optString("extra", ""),
                    )
                }
                val logs = MobileBridge.getLogsText()
                diagItems = parsed
                logsText  = logs
            } catch (_: Exception) {}
        }
        isRefreshing = false
    }

    fun buildFullReport(): String {
        val sb = StringBuilder()
        sb.append("=== 🩺 ДИАГНОСТИКА СЕТИ NATBYPASS ===\n")
        diagItems.forEach { item ->
            val mark = if (item.ok) "✅" else "⚠️"
            sb.append("$mark ${item.label}: ${item.detail}")
            if (item.extra.isNotEmpty()) sb.append(" (${item.extra})")
            sb.append("\n")
        }
        sb.append("\n=== 📋 ЖУРНАЛ ЯДРА ===\n")
        sb.append(logsText.ifEmpty { "(логи пусты)" })
        return sb.toString()
    }

    fun copyToClipboard() {
        val report = buildFullReport()
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("NatBypass Diagnostics", report))
        Toast.makeText(context, "📋 Отчет и логи скопированы в буфер!", Toast.LENGTH_SHORT).show()
    }

    fun shareReport() {
        val report = buildFullReport()
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "NatBypass Диагностика и логи")
            putExtra(Intent.EXTRA_TEXT, report)
        }
        context.startActivity(Intent.createChooser(sendIntent, "Поделиться диагностикой"))
    }

    // Initial load + auto-poll RTT
    LaunchedEffect(Unit) {
        loadOnce()
        while (true) {
            delay(3000)
            withContext(Dispatchers.IO) {
                try {
                    val peerStr = MobileBridge.getPeersJSON()
                    val arr = org.json.JSONArray(peerStr)
                    var total = 0L; var cnt = 0
                    for (i in 0 until arr.length()) {
                        val p = arr.getJSONObject(i)
                        val ms = p.optLong("ping_ms", 0L)
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
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, "Назад")
                    }
                },
                actions = {
                    IconButton(onClick = ::copyToClipboard) {
                        Icon(Icons.Outlined.ContentCopy, "Скопировать")
                    }
                    IconButton(onClick = ::shareReport) {
                        Icon(Icons.Outlined.Share, "Поделиться")
                    }
                    if (isRefreshing) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .size(24.dp)
                                .padding(end = 8.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        IconButton(onClick = { scope.launch { loadOnce() } }) {
                            Icon(Icons.Outlined.Refresh, "Обновить")
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
            )
        }
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            // ── Network checks ───────────────────────────────────────────────
            SectionTitle("Сетевая диагностика")
            diagItems.forEach { DiagRow(it) }
            if (diagItems.isEmpty() && !isRefreshing) {
                Text(
                    text = "Нет данных",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            }

            Spacer(Modifier.height(16.dp))

            // ── RTT history chart ────────────────────────────────────────────
            SectionTitle("История RTT")
            Spacer(Modifier.height(8.dp))
            RttChart(
                values   = rttHistory,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(130.dp)
            )

            Spacer(Modifier.height(16.dp))

            // ── Logs ─────────────────────────────────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionTitle("Журнал ядра")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AssistChip(
                        onClick = ::copyToClipboard,
                        label = { Text("Копировать", fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Outlined.ContentCopy, null, modifier = Modifier.size(14.dp)) }
                    )
                    AssistChip(
                        onClick = ::shareReport,
                        label = { Text("Поделиться", fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Outlined.Share, null, modifier = Modifier.size(14.dp)) }
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            Surface(
                shape  = RoundedCornerShape(12.dp),
                color  = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text  = logsText.ifEmpty { "Логи пусты" },
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily  = FontFamily.Monospace,
                        fontSize    = 11.sp,
                        lineHeight  = 16.sp,
                    ),
                    color    = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(12.dp),
                )
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text       = text,
        style      = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier   = Modifier.padding(bottom = 2.dp),
    )
}

@Composable
private fun DiagRow(item: DiagItem) {
    Row(
        modifier  = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            imageVector = if (item.ok) Icons.Filled.CheckCircle else Icons.Filled.Warning,
            contentDescription = null,
            tint     = if (item.ok) MaterialTheme.natColors.success else MaterialTheme.natColors.warning,
            modifier = Modifier
                .size(20.dp)
                .padding(top = 2.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column {
            Text(
                text       = item.label,
                fontWeight = FontWeight.Medium,
                style      = MaterialTheme.typography.bodyMedium,
            )
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

    Surface(
        modifier  = modifier,
        shape     = RoundedCornerShape(16.dp),
        color     = surfaceColor.copy(alpha = 0.5f),
    ) {
        if (values.size < 2) {
            Box(
                contentAlignment = Alignment.Center,
                modifier         = Modifier.fillMaxSize(),
            ) {
                Text(
                    text      = "Недостаточно данных",
                    style     = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    color     = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                )
            }
        } else {
            Canvas(modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)) {
                val maxVal = values.maxOrNull()?.takeIf { it > 0 } ?: 1f
                val w      = size.width
                val h      = size.height
                val step   = w / (values.size - 1)

                val path = Path()
                values.forEachIndexed { i, v ->
                    val x = i * step
                    val y = h - (v / maxVal) * h
                    if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
                }
                drawPath(
                    path  = path,
                    color = primaryColor,
                    style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                )
                values.forEachIndexed { i, v ->
                    drawCircle(
                        color  = primaryColor,
                        radius = 4.dp.toPx(),
                        center = Offset(i * step, h - (v / maxVal) * h)
                    )
                }
            }
        }
    }
}
