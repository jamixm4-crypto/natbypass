package org.natbypass.app.ui.compose

import android.content.Context
import android.content.SharedPreferences
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
import org.json.JSONArray
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
    var virtualIp       by remember { mutableStateOf(prefs.getString("virtual_ip", "") ?: "") }
    var publishInterval by remember { mutableStateOf(prefs.getInt("publish_interval", 8).toString()) }
    var autoStart       by remember { mutableStateOf(prefs.getBoolean("auto_start_on_boot", false)) }
    var saveLogs        by remember { mutableStateOf(prefs.getBoolean("save_logs", false)) }

    // Routing & Network Sharing settings
    var allowExitNode   by remember { mutableStateOf(prefs.getBoolean("allow_exit_node", false)) }
    var advSubnets      by remember { mutableStateOf(prefs.getString("adv_subnets", "") ?: "") }
    var detectedSubnets by remember { mutableStateOf<List<String>>(emptyList()) }

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

    var betaChannel     by remember { mutableStateOf(prefs.getBoolean("beta_channel", false)) }
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
    val versionName     = remember {
        try { context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.9.221-beta.8" }
        catch (_: Exception) { "1.9.221-beta.8" }
    }

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
                virtualIp         = active.optString("virtual_ip", MobileBridge.getVirtualIP())
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
                virtualIp   = prefs.getString("virtual_ip", MobileBridge.getVirtualIP()) ?: MobileBridge.getVirtualIP()
                mqttUser    = prefs.getString("mqtt_user", "") ?: ""
                mqttPass    = prefs.getString("mqtt_pass", "") ?: ""
                tgToken     = prefs.getString("tg_token", "") ?: ""
                tgChat      = prefs.getString("tg_chat", "") ?: ""
                tgProxy     = prefs.getString("tg_proxy", "") ?: ""
                awgPreset   = prefs.getString("awg_preset", "dpi") ?: "dpi"
            }

            val rawSubnets = MobileBridge.getLocalSubnetsJSON()
            val arr = JSONArray(rawSubnets)
            val list = mutableListOf<String>()
            for (i in 0 until arr.length()) {
                list.add(arr.getString(i))
            }
            detectedSubnets = list
        } catch (_: Exception) {}
    }

    // Custom AWG parameters
    var awgJc   by remember { mutableStateOf(prefs.getString("awg_jc", "4") ?: "4") }
    var awgJmin by remember { mutableStateOf(prefs.getString("awg_jmin", "40") ?: "40") }
    var awgJmax by remember { mutableStateOf(prefs.getString("awg_jmax", "70") ?: "70") }
    var awgS1   by remember { mutableStateOf(prefs.getString("awg_s1", "48") ?: "48") }
    var awgS2   by remember { mutableStateOf(prefs.getString("awg_s2", "32") ?: "32") }
    var awgH1   by remember { mutableStateOf(prefs.getString("awg_h1", "1428571428") ?: "1428571428") }
    var awgH2   by remember { mutableStateOf(prefs.getString("awg_h2", "2147483647") ?: "2147483647") }
    var awgH3   by remember { mutableStateOf(prefs.getString("awg_h3", "857142857") ?: "857142857") }
    var awgH4   by remember { mutableStateOf(prefs.getString("awg_h4", "1122334455") ?: "1122334455") }

    var showImportBackupDialog by remember { mutableStateOf(false) }
    var backupImportText by remember { mutableStateOf("") }

    fun save() {
        prefs.edit().apply {
            putString("device_name", deviceName.trim())
            putString("virtual_ip", virtualIp.trim())
            putInt("publish_interval", publishInterval.toIntOrNull() ?: 8)
            putBoolean("auto_start_on_boot", autoStart)
            putBoolean("save_logs", saveLogs)
            putBoolean("allow_exit_node", allowExitNode)
            putString("adv_subnets", advSubnets.trim())
            putString("awg_preset", awgPreset)
            putString("awg_jc", awgJc.trim())
            putString("awg_jmin", awgJmin.trim())
            putString("awg_jmax", awgJmax.trim())
            putString("awg_s1", awgS1.trim())
            putString("awg_s2", awgS2.trim())
            putString("awg_h1", awgH1.trim())
            putString("awg_h2", awgH2.trim())
            putString("awg_h3", awgH3.trim())
            putString("awg_h4", awgH4.trim())
            putString("mqtt_broker", mqttBroker.trim())
            putString("mqtt_topic", mqttTopic.trim())
            putString("mqtt_user", mqttUser.trim())
            putString("mqtt_pass", mqttPass)
            putString("tg_token", tgToken.trim())
            putString("tg_chat", tgChat.trim())
            putString("tg_proxy", tgProxy.trim())
            apply()
        }

        MobileBridge.setAllowExitNode(allowExitNode)
        MobileBridge.setAdvertisedRoutes(advSubnets.trim())

        if (virtualIp.isNotBlank()) {
            MobileBridge.setVirtualIP(virtualIp.trim())
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

        if (awgPreset == "custom") {
            MobileBridge.setAWGCustom(
                awgJc.toIntOrNull() ?: 4,
                awgJmin.toIntOrNull() ?: 40,
                awgJmax.toIntOrNull() ?: 70,
                awgS1.toIntOrNull() ?: 48,
                awgS2.toIntOrNull() ?: 32,
                awgH1.trim(), awgH2.trim(), awgH3.trim(), awgH4.trim()
            )
        } else {
            MobileBridge.setAWGPreset(awgPreset)
        }

        try {
            val yaml = MobileBridge.getConfigYAML()
            if (yaml.isNotEmpty() && yaml != "{}") {
                File(context.filesDir, "config.yaml").writeText(yaml)
            }
        } catch (_: Exception) {}

        Toast.makeText(context, "✓ Настройки сохранены", Toast.LENGTH_SHORT).show()
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
            // ── Update & Beta Channel (Top Priority) ───────────────────────
            SettingsSection(title = "Канал обновлений (Beta) и версия", icon = Icons.Outlined.CloudDownload) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(text = "NatBypass Mesh Network", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Text(text = "Версия v$versionName (P2P Mesh + AWG 2.0)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (betaChannel) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = MaterialTheme.colorScheme.errorContainer
                        ) {
                            Text(
                                text = "BETA КАНАЛ",
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                SettingsSwitch(
                    title = "Тестовые сборки (Beta)",
                    subtitle = "Получать предварительные обновления. Могут содержать экспериментальные фичи и работать нестабильно!",
                    icon = Icons.Outlined.Science,
                    checked = betaChannel,
                    onCheckedChange = { checked ->
                        betaChannel = checked
                        prefs.edit().putBoolean("beta_channel", checked).apply()
                    }
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onCheckUpdate,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Outlined.CloudDownload, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(if (betaChannel) "Проверить обновления (Beta-канал)" else "Проверить обновления на GitHub")
                }
            }

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

            // ── Routing & Network Sharing ─────────────────────────────────
            SettingsSection(title = "Маршрутизация и расшаривание сети", icon = Icons.Outlined.AltRoute) {
                SettingsSwitch(
                    title = "Разрешить выход в интернет (Exit Node)",
                    subtitle = "Другие компьютеры и телефоны смогут выходить в интернет через этот телефон",
                    icon = Icons.Outlined.Public,
                    checked = allowExitNode,
                    onCheckedChange = {
                        allowExitNode = it
                        MobileBridge.setAllowExitNode(it)
                    },
                )
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Spacer(Modifier.height(4.dp))

                Text(
                    text = "Расшарить локальные подсети (Subnet Routing)",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "Открывает доступ к устройствам в вашей локальной Wi-Fi сети для других узлов mesh-сети",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))

                if (detectedSubnets.isNotEmpty()) {
                    Text(
                        text = "Обнаруженные локальные сети:",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        detectedSubnets.forEach { subnet ->
                            AssistChip(
                                onClick = {
                                    val currentList = advSubnets.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
                                    if (!currentList.contains(subnet)) {
                                        currentList.add(subnet)
                                        advSubnets = currentList.joinToString(", ")
                                    }
                                },
                                label = { Text("+ $subnet", fontSize = 12.sp) }
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }

                OutlinedTextField(
                    value = advSubnets,
                    onValueChange = { advSubnets = it },
                    label = { Text("Анонсируемые подсети (CIDR через запятую)") },
                    placeholder = { Text("192.168.1.0/24") },
                    leadingIcon = { Icon(Icons.Outlined.Lan, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // ── Device ────────────────────────────────────────────────────
            SettingsSection(title = "Устройство", icon = Icons.Outlined.PhoneAndroid) {
                OutlinedTextField(
                    value = virtualIp,
                    onValueChange = { virtualIp = it },
                    label = { Text("Виртуальный IP (Virtual IP)") },
                    placeholder = { Text("100.64.200.10/24") },
                    leadingIcon = { Icon(Icons.Outlined.Fingerprint, null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
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
                val presets = listOf(
                    "standard" to "Стандарт",
                    "dpi"      to "Обход DPI",
                    "stealth"  to "Скрытность",
                    "custom"   to "Кастомный"
                )
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    presets.forEachIndexed { idx, (key, label) ->
                        SegmentedButton(
                            selected = awgPreset == key,
                            onClick  = { awgPreset = key },
                            shape = SegmentedButtonDefaults.itemShape(index = idx, count = presets.size),
                        ) { Text(label, fontSize = 11.sp) }
                    }
                }

                if (awgPreset == "custom") {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = "Параметры обфускации (Junk & Headers)",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = awgJc,
                            onValueChange = { awgJc = it },
                            label = { Text("Jc (пакеты)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = awgJmin,
                            onValueChange = { awgJmin = it },
                            label = { Text("Jmin (байт)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = awgJmax,
                            onValueChange = { awgJmax = it },
                            label = { Text("Jmax (байт)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = awgS1,
                            onValueChange = { awgS1 = it },
                            label = { Text("S1 (Init magic)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = awgS2,
                            onValueChange = { awgS2 = it },
                            label = { Text("S2 (Resp magic)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = awgH1,
                            onValueChange = { awgH1 = it },
                            label = { Text("H1 (Handshake)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = awgH2,
                            onValueChange = { awgH2 = it },
                            label = { Text("H2 (Response)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
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

            // ── Backup & Restore ──────────────────────────────────────────
            SettingsSection(title = "Резервные копии сетей", icon = Icons.Outlined.Backup) {
                Text(
                    text = "Экспорт и импорт всех настроенных профилей и ключей",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val jsonBackup = MobileBridge.exportAllProfilesJSON()
                            if (jsonBackup.isNotEmpty() && jsonBackup != "[]") {
                                val sendIntent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(android.content.Intent.EXTRA_SUBJECT, "NatBypass Profiles Backup")
                                    putExtra(android.content.Intent.EXTRA_TEXT, jsonBackup)
                                }
                                context.startActivity(android.content.Intent.createChooser(sendIntent, "Экспорт профилей"))
                            } else {
                                Toast.makeText(context, "Нет сохраненных сетей для экспорта", Toast.LENGTH_SHORT).show()
                            }
                        },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Outlined.FileDownload, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Экспорт (JSON)", fontSize = 12.sp)
                    }

                    Button(
                        onClick = { showImportBackupDialog = true },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Outlined.FileUpload, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Импорт", fontSize = 12.sp)
                    }
                }
            }

            // ── App info ───────────────────────────────────────────────────
            SettingsSection(title = "О приложении", icon = Icons.Outlined.Info) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(text = "NatBypass Mesh Network", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                        Text(text = "Версия v$versionName • Android • Pure Go Core", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            Spacer(Modifier.height(40.dp))
        }

        if (showImportBackupDialog) {
            AlertDialog(
                onDismissRequest = { showImportBackupDialog = false },
                title = { Text("Импорт сетей из Backup JSON") },
                text = {
                    Column {
                        Text(
                            text = "Вставьте скопированный JSON бэкапа профилей:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = backupImportText,
                            onValueChange = { backupImportText = it },
                            placeholder = { Text("[{\"id\":\"p-1\",\"name\":\"Сеть 1\"...}]") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(140.dp),
                            maxLines = 6
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val res = MobileBridge.importAllProfilesJSON(backupImportText.trim())
                            if (res == "OK") {
                                try {
                                    val yaml = MobileBridge.getConfigYAML()
                                    if (yaml.isNotEmpty()) File(context.filesDir, "config.yaml").writeText(yaml)
                                } catch (_: Exception) {}
                                Toast.makeText(context, "✓ Профили успешно импортированы!", Toast.LENGTH_SHORT).show()
                                showImportBackupDialog = false
                                backupImportText = ""
                            } else {
                                Toast.makeText(context, res, Toast.LENGTH_LONG).show()
                            }
                        }
                    ) {
                        Text("Импортировать")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showImportBackupDialog = false }) {
                        Text("Отмена")
                    }
                }
            )
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
