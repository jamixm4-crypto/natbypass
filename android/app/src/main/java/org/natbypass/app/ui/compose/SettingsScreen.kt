package org.natbypass.app.ui.compose

import android.content.Context
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import org.natbypass.app.ui.compose.AppTheme
import org.natbypass.app.util.MobileBridge
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    currentTheme: AppTheme,
    dynamicColorEnabled: Boolean,
    onThemeChange: (AppTheme) -> Unit,
    onDynamicColorChange: (Boolean) -> Unit,
    onCheckUpdate: () -> Unit,
) {
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

    // Load active profile data from MobileBridge
    var activeProfileId   by remember { mutableStateOf("") }
    var activeProfileName by remember { mutableStateOf("Основная сеть") }

    // Device / App settings (stored in SharedPreferences)
    var deviceName      by remember { mutableStateOf(prefs.getString("device_name", Build.MODEL) ?: Build.MODEL) }
    var publishInterval by remember { mutableStateOf(prefs.getInt("publish_interval", 8).toString()) }
    var autoStart       by remember { mutableStateOf(prefs.getBoolean("auto_start_on_boot", false)) }
    var saveLogs        by remember { mutableStateOf(prefs.getBoolean("save_logs", false)) }

    // Network / Profile settings (loaded from Active Profile)
    var awgPreset       by remember { mutableStateOf("dpi") }
    var mqttBroker      by remember { mutableStateOf("tcp://broker.emqx.io:1883") }
    var mqttTopic       by remember { mutableStateOf("natbypass/mynet/peers") }
    var mqttUser        by remember { mutableStateOf("") }
    var mqttPass        by remember { mutableStateOf("") }
    var mqttPassVisible by remember { mutableStateOf(false) }

    // Telegram
    var tgToken         by remember { mutableStateOf("") }
    var tgChat          by remember { mutableStateOf("") }
    var tgProxy         by remember { mutableStateOf("") }

    // Initialize from Active Profile in MobileBridge
    LaunchedEffect(Unit) {
        try {
            val profJson = MobileBridge.getProfilesJSON()
            val pObj = JSONObject(profJson)
            val active = pObj.optJSONObject("active_profile")
            if (active != null) {
                activeProfileId   = active.optString("id", "")
                activeProfileName = active.optString("name", "Основная сеть")
                mqttBroker        = active.optString("mqtt_broker", "tcp://broker.emqx.io:1883")
                mqttTopic         = active.optString("mqtt_topic", "")
                mqttUser          = active.optString("mqtt_user", "")
                mqttPass          = active.optString("mqtt_pass", "")
                tgToken           = active.optString("tg_token", "")
                val chatVal       = active.optLong("tg_chat_id", 0L)
                tgChat            = if (chatVal != 0L) chatVal.toString() else ""
                tgProxy           = active.optString("tg_proxy", "")
                awgPreset         = active.optString("awg_preset", prefs.getString("awg_preset", "dpi") ?: "dpi")
            } else {
                mqttBroker  = prefs.getString("mqtt_broker", "tcp://broker.emqx.io:1883") ?: ""
                mqttTopic   = prefs.getString("mqtt_topic", "natbypass/mynet/peers") ?: ""
                mqttUser    = prefs.getString("mqtt_user", "") ?: ""
                mqttPass    = prefs.getString("mqtt_pass", "") ?: ""
                tgToken     = prefs.getString("tg_token", "") ?: ""
                tgChat      = prefs.getString("tg_chat", "") ?: ""
                tgProxy     = prefs.getString("tg_proxy", "") ?: ""
                awgPreset   = prefs.getString("awg_preset", "dpi") ?: "dpi"
            }
        } catch (_: Exception) {}
    }

    fun save() {
        prefs.edit().apply {
            putString("device_name", deviceName.trim())
            putInt("publish_interval", publishInterval.toIntOrNull() ?: 8)
            putBoolean("auto_start_on_boot", autoStart)
            putBoolean("save_logs", saveLogs)
            putString("awg_preset", awgPreset)
            putString("mqtt_broker", mqttBroker.trim())
            putString("mqtt_topic", mqttTopic.trim())
            putString("mqtt_user", mqttUser.trim())
            putString("mqtt_pass", mqttPass)
            putString("tg_token", tgToken.trim())
            putString("tg_chat", tgChat.trim())
            putString("tg_proxy", tgProxy.trim())
            apply()
        }

        if (activeProfileId.isNotEmpty()) {
            MobileBridge.updateProfile(
                activeProfileId,
                activeProfileName,
                mqttBroker.trim(),
                mqttTopic.trim(),
                mqttUser.trim(),
                mqttPass,
                tgToken.trim(),
                tgChat.trim().toLongOrNull() ?: 0L,
                tgProxy.trim(),
                awgPreset
            )
        }

        MobileBridge.setAWGPreset(awgPreset)

        try {
            val yaml = MobileBridge.getConfigYAML()
            if (yaml.isNotEmpty() && yaml != "{}") {
                File(context.filesDir, "config.yaml").writeText(yaml)
            }
        } catch (_: Exception) {}

        Toast.makeText(context, "✓ Настройки сети «$activeProfileName» сохранены", Toast.LENGTH_SHORT).show()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Настройки", fontWeight = FontWeight.Bold, fontSize = 20.sp)
                        if (activeProfileName.isNotEmpty()) {
                            Text(
                                text = "Профиль: $activeProfileName",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, "Назад")
                    }
                },
                actions = {
                    IconButton(onClick = ::save) {
                        Icon(Icons.Filled.Check, contentDescription = "Сохранить", tint = MaterialTheme.colorScheme.primary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
        bottomBar = {
            Surface(
                shadowElevation = 8.dp,
                tonalElevation = 3.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .navigationBarsPadding()
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                ) {
                    Button(
                        onClick = ::save,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Icon(Icons.Filled.Save, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Сохранить настройки", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                    }
                }
            }
        }
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ── Appearance ─────────────────────────────────────────────────
            SettingsSection(title = "Внешний вид", icon = Icons.Outlined.Palette) {
                Text(
                    text = "Тема оформления",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    listOf(AppTheme.SYSTEM to "Авто", AppTheme.LIGHT to "Светлая", AppTheme.DARK to "Тёмная")
                        .forEachIndexed { idx, (theme, label) ->
                            SegmentedButton(
                                selected = currentTheme == theme,
                                onClick  = { onThemeChange(theme) },
                                shape = SegmentedButtonDefaults.itemShape(index = idx, count = 3),
                            ) { Text(label) }
                        }
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    Spacer(Modifier.height(8.dp))
                    SettingsSwitch(
                        title = "Dynamic Color",
                        subtitle = "Использовать цвета обоев (Material You)",
                        icon = Icons.Outlined.ColorLens,
                        checked = dynamicColorEnabled,
                        onCheckedChange = onDynamicColorChange,
                    )
                }
            }

            // ── Device ────────────────────────────────────────────────────
            SettingsSection(title = "Устройство", icon = Icons.Outlined.PhoneAndroid) {
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it },
                    label = { Text("Имя устройства") },
                    leadingIcon = { Icon(Icons.Outlined.DeviceHub, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = publishInterval,
                    onValueChange = { publishInterval = it },
                    label = { Text("Интервал публикации (сек)") },
                    leadingIcon = { Icon(Icons.Outlined.Timer, null) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                SettingsSwitch(
                    title = "Автозапуск при загрузке",
                    subtitle = "Запускать VPN при включении телефона",
                    icon = Icons.Outlined.Autorenew,
                    checked = autoStart,
                    onCheckedChange = { autoStart = it },
                )
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        try {
                            val intent = android.content.Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                data = android.net.Uri.parse("package:${context.packageName}")
                            }
                            context.startActivity(intent)
                        } catch (_: Exception) {
                            try {
                                context.startActivity(android.content.Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                            } catch (_: Exception) {}
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Outlined.BatteryChargingFull, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Работа в фоне (без ограничений)", fontSize = 12.sp)
                }
            }

            // ── Network / Protocol ────────────────────────────────────────
            SettingsSection(title = "Сеть и протокол", icon = Icons.Outlined.Tune) {
                Text(
                    text = "Пресет AmneziaWG 2.0",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                val presets = listOf("standard" to "Стандарт", "dpi" to "Обход DPI", "stealth" to "Скрытность")
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    presets.forEachIndexed { idx, (key, label) ->
                        SegmentedButton(
                            selected = awgPreset == key,
                            onClick  = { awgPreset = key },
                            shape = SegmentedButtonDefaults.itemShape(index = idx, count = presets.size),
                        ) { Text(label) }
                    }
                }
            }

            // ── MQTT ──────────────────────────────────────────────────────
            SettingsSection(title = "MQTT Брокер ($activeProfileName)", icon = Icons.Outlined.Cloud) {
                val brokerPresets = listOf(
                    "tcp://broker.emqx.io:1883",
                    "tcp://broker.hivemq.com:1883",
                    "tcp://test.mosquitto.org:1883",
                )
                OutlinedTextField(
                    value = mqttBroker,
                    onValueChange = { mqttBroker = it },
                    label = { Text("URL брокера") },
                    leadingIcon = { Icon(Icons.Outlined.Link, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    brokerPresets.take(2).forEach { preset ->
                        AssistChip(
                            onClick = { mqttBroker = preset },
                            label = { Text(preset.removePrefix("tcp://").substringBefore(":"), style = MaterialTheme.typography.labelSmall) },
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = mqttTopic,
                    onValueChange = { mqttTopic = it },
                    label = { Text("Топик сети") },
                    leadingIcon = { Icon(Icons.Outlined.Tag, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = mqttUser,
                    onValueChange = { mqttUser = it },
                    label = { Text("Логин (если требуется)") },
                    leadingIcon = { Icon(Icons.Outlined.Person, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = mqttPass,
                    onValueChange = { mqttPass = it },
                    label = { Text("Пароль (если требуется)") },
                    leadingIcon = { Icon(Icons.Outlined.Lock, null) },
                    trailingIcon = {
                        IconButton(onClick = { mqttPassVisible = !mqttPassVisible }) {
                            Icon(if (mqttPassVisible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, null)
                        }
                    },
                    visualTransformation = if (mqttPassVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // ── Telegram ──────────────────────────────────────────────────
            SettingsSection(title = "Telegram ($activeProfileName)", icon = Icons.Outlined.Send) {
                OutlinedTextField(
                    value = tgToken,
                    onValueChange = { tgToken = it },
                    label = { Text("Bot Token") },
                    leadingIcon = { Icon(Icons.Outlined.VpnKey, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = tgChat,
                    onValueChange = { tgChat = it },
                    label = { Text("Chat ID") },
                    leadingIcon = { Icon(Icons.Outlined.Tag, null) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = tgProxy,
                    onValueChange = { tgProxy = it },
                    label = { Text("Прокси (необязательно)") },
                    leadingIcon = { Icon(Icons.Outlined.Router, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // ── App info & Updates ─────────────────────────────────────────
            SettingsSection(title = "О приложении и обновления", icon = Icons.Outlined.Info) {
                val versionName = try {
                    context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.3.0"
                } catch (_: Exception) { "1.3.0" }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(text = "NatBypass Mesh", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Text(text = "Версия v$versionName (P2P Mesh + AWG 2.0)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Spacer(Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onCheckUpdate,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Outlined.CloudDownload, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Проверить обновления на GitHub")
                }
            }

            Spacer(Modifier.height(40.dp))
        }
    }
}

// ── Settings section container ─────────────────────────────────────────────────
@Composable
private fun SettingsSection(
    title: String,
    icon: ImageVector,
    content: @Composable ColumnScope.() -> Unit,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}

// ── Settings switch row ────────────────────────────────────────────────────────
@Composable
private fun SettingsSwitch(
    title: String,
    subtitle: String,
    icon: ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
