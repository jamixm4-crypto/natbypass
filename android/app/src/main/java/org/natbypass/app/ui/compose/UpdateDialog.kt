package org.natbypass.app.ui.compose

import android.content.Context
import android.content.SharedPreferences
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.natbypass.app.util.AppUpdateManager
import org.natbypass.app.util.UpdateState
import java.util.Locale

@Composable
fun UpdateDialog(
    state: UpdateState,
    onDownload: (version: String, url: String, size: Long) -> Unit,
    onCancelDownload: () -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE) }
    var betaChannel by remember { mutableStateOf(prefs.getBoolean("beta_channel", false)) }

    LaunchedEffect(state) {
        betaChannel = prefs.getBoolean("beta_channel", false)
    }

    DisposableEffect(prefs) {
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { sp, key ->
            if (key == "beta_channel") {
                betaChannel = sp.getBoolean("beta_channel", false)
            }
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        onDispose {
            prefs.unregisterOnSharedPreferenceChangeListener(listener)
        }
    }

    when (state) {
        is UpdateState.Idle -> {}

        is UpdateState.Checking -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { Text("Проверка обновлений") },
                text = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                        modifier = Modifier.padding(vertical = 8.dp)
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(32.dp))
                        Text("Связываемся с GitHub Releases...")
                    }
                },
                confirmButton = {},
                dismissButton = {
                    TextButton(onClick = onDismiss) { Text("Отмена") }
                }
            )
        }

        is UpdateState.Available -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                icon = {
                    Icon(
                        imageVector = if (state.isNewer) Icons.Filled.Celebration else Icons.Outlined.CloudSync,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(32.dp)
                    )
                },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        val titleStr = when {
                            state.isRollback -> "Откат на стабильную: v${state.version}"
                            state.isNewer -> "Доступно обновление: v${state.version}"
                            else -> "Текущий билд: v${state.version}"
                        }
                        Text(
                            text = titleStr,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (state.isPrerelease) {
                            Spacer(Modifier.width(8.dp))
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = MaterialTheme.colorScheme.errorContainer
                            ) {
                                Text(
                                    text = "BETA",
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }
                },
                text = {
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        if (state.sizeBytes > 0) {
                            val mb = state.sizeBytes.toFloat() / (1024 * 1024)
                            Text(
                                text = "Размер файла: ${String.format(Locale.US, "%.1f", mb)} MB",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Medium
                            )
                            Spacer(Modifier.height(8.dp))
                        }
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 200.dp)
                        ) {
                            Column(
                                modifier = Modifier
                                    .padding(10.dp)
                                    .verticalScroll(rememberScrollState())
                            ) {
                                Text(
                                    text = state.changelog,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        text = "🧪 Тестовые сборки (Beta)",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.SemiBold,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Switch(
                                        checked = betaChannel,
                                        onCheckedChange = { checked ->
                                            betaChannel = checked
                                            prefs.edit().putBoolean("beta_channel", checked).apply()
                                            val curVer = try {
                                                context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.3.0"
                                            } catch (_: Exception) { "1.3.0" }
                                            coroutineScope.launch {
                                                AppUpdateManager.checkForUpdates(curVer, manual = true, includePrerelease = checked)
                                            }
                                        }
                                    )
                                }
                                if (betaChannel) {
                                    Spacer(Modifier.height(4.dp))
                                    Text(
                                        text = "⚠️ Внимание: тестовые сборки содержат новейшие экспериментальные функции, но могут работать нестабильно.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                        }
                    }
                },

                confirmButton = {
                    var isStartingDownload by remember { mutableStateOf(false) }
                    Button(
                        onClick = {
                            if (!isStartingDownload) {
                                isStartingDownload = true
                                onDownload(state.version, state.apkUrl, state.sizeBytes)
                            }
                        },
                        enabled = !isStartingDownload,
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isStartingDownload) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("Подключение...")
                        } else {
                            Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            val btnLabel = when {
                                state.isRollback -> "Откатиться на стабильную"
                                state.isPrerelease -> "Скачать Beta-версию"
                                else -> "Скачать и обновить"
                            }
                            Text(btnLabel)
                        }
                    }
                },
                dismissButton = {
                    OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(12.dp)) {
                        Text("Позже")
                    }
                }
            )
        }

        is UpdateState.Downloading -> {
            AlertDialog(
                onDismissRequest = onCancelDownload,
                title = {
                    Text("Загрузка обновления v${state.version}", fontWeight = FontWeight.Bold)
                },
                text = {
                    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                        // Progress bar
                        LinearProgressIndicator(
                            progress = state.progress,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp),
                            color = MaterialTheme.colorScheme.primary,
                            trackColor = MaterialTheme.colorScheme.surfaceVariant,
                        )
                        Spacer(Modifier.height(12.dp))

                        // Downloaded MB / Total MB + percent
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "${String.format(Locale.US, "%.1f", state.downloadedMB)} MB из ${String.format(Locale.US, "%.1f", state.totalMB)} MB",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "${(state.progress * 100).toInt()}%",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }

                        Spacer(Modifier.height(6.dp))

                        // Speed and ETA
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "⚡ ${String.format(Locale.US, "%.2f", state.speedMBs)} MB/с",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            val etaText = when {
                                state.etaSec > 60 -> "~${state.etaSec / 60} мин"
                                state.etaSec > 0  -> "~${state.etaSec} сек"
                                else              -> "завершение..."
                            }
                            Text(
                                text = "⏱ $etaText",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                confirmButton = {},
                dismissButton = {
                    TextButton(onClick = onCancelDownload) {
                        Text("Отменить")
                    }
                }
            )
        }

        is UpdateState.ReadyToInstall -> {
            // Handled automatically by launching package installer
        }

        is UpdateState.Error -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                icon = {
                    Icon(
                        imageVector = Icons.Filled.ErrorOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(32.dp)
                    )
                },
                title = { Text("Ошибка обновления") },
                text = {
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                },
                confirmButton = {
                    Button(onClick = onDismiss) { Text("Понятно") }
                }
            )
        }
    }
}
