package org.natbypass.app.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color as AColor
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.launch
import org.natbypass.app.R
import org.natbypass.app.ui.compose.*
import org.natbypass.app.util.AppUpdateManager
import org.natbypass.app.util.MobileBridge
import org.natbypass.app.util.UpdateState
import java.io.File
import java.io.FileOutputStream

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startVpn(this)
        } else {
            Toast.makeText(this, getString(R.string.vpn_permission_denied), Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            var appTheme by remember {
                mutableStateOf(
                    AppTheme.values().getOrElse(prefs.getInt("app_theme", 0)) { AppTheme.SYSTEM }
                )
            }
            var dynamicColor by remember { mutableStateOf(prefs.getBoolean("dynamic_color", true)) }

            NatBypassTheme(appTheme = appTheme, dynamicColor = dynamicColor) {
                NatBypassApp(
                    viewModel = viewModel,
                    onVpnToggle = {
                        viewModel.onVpnToggleClick(this) { vpnPermissionLauncher.launch(it) }
                    },
                    appTheme = appTheme,
                    dynamicColorEnabled = dynamicColor,
                    onThemeChange = { t ->
                        appTheme = t
                        prefs.edit().putInt("app_theme", t.ordinal).apply()
                    },
                    onDynamicColorChange = { d ->
                        dynamicColor = d
                        prefs.edit().putBoolean("dynamic_color", d).apply()
                    },
                    onShareQR = { showShareQRDialog() },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.syncNetwork()
    }

    private fun showShareQRDialog() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        val devName = prefs.getString("device_name", android.os.Build.MODEL ?: "Android-Node")
        val inviteText = "NatBypass|$devName|https://github.com/jamixm4-crypto/natbypass/releases/latest"
        shareQRPayload(inviteText)
    }

    fun shareQRPayload(payload: String) {
        try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(payload, BarcodeFormat.QR_CODE, 512, 512)
            val w = bitMatrix.width; val h = bitMatrix.height
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565)
            for (x in 0 until w) for (y in 0 until h) {
                bmp.setPixel(x, y, if (bitMatrix.get(x, y)) AColor.BLACK else AColor.WHITE)
            }
            val qrFile = File(cacheDir, "qr_share.png")
            FileOutputStream(qrFile).use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
            val uri = FileProvider.getUriForFile(this, "$packageName.provider", qrFile)
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "image/png"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_TEXT, payload)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(shareIntent, "Поделиться QR-кодом"))
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка создания QR: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}

// ── App-level navigation composable ───────────────────────────────────────────
@Composable
private fun NatBypassApp(
    viewModel: MainViewModel,
    onVpnToggle: () -> Unit,
    appTheme: AppTheme,
    dynamicColorEnabled: Boolean,
    onThemeChange: (AppTheme) -> Unit,
    onDynamicColorChange: (Boolean) -> Unit,
    onShareQR: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val activity = context as? MainActivity
    val coroutineScope = rememberCoroutineScope()
    val updateState by AppUpdateManager.updateState.collectAsState()

    var currentScreen by remember { mutableStateOf<Screen>(Screen.Main) }
    var showProfileSheet by remember { mutableStateOf(false) }
    var showProfileEdit by remember { mutableStateOf<ProfileEditMode?>(null) }
    var showImportDialog by remember { mutableStateOf(false) }

    val checkUpdate: () -> Unit = {
        val currentVersion = try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.3.0"
        } catch (_: Exception) { "1.3.0" }
        coroutineScope.launch {
            AppUpdateManager.checkForUpdates(currentVersion, manual = true)
        }
    }

    when (currentScreen) {
        Screen.Main -> MainScreen(
            uiState = uiState,
            onToggleVpn = onVpnToggle,
            onPeerPing = { peer ->
                viewModel.pingPeer(peer.id) { rtt ->
                    val msg = if (rtt >= 0) "RTT: $rtt мс" else "Узел не ответил"
                    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                }
            },
            onPeerCopyIp = { peer ->
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("Peer VIP", peer.virtualIp))
                Toast.makeText(context, "IP ${peer.virtualIp} скопирован", Toast.LENGTH_SHORT).show()
            },
            onPeerSetExitNode = { peer ->
                viewModel.setExitNode(context, peer.id)
                Toast.makeText(context, "Exit Node: ${peer.displayName}", Toast.LENGTH_SHORT).show()
            },
            onPeerDelete = { peer -> viewModel.deletePeer(peer.id) },
            onOpenProfiles = { showProfileSheet = true },
            onOpenDiagnostics = { currentScreen = Screen.Diagnostics },
            onOpenSettings = { currentScreen = Screen.Settings },
            onOpenQRScanner = {
                context.startActivity(Intent(context, QRScannerActivity::class.java))
            },
            onShareQR = onShareQR,
            onSync = {
                viewModel.syncNetwork()
                Toast.makeText(context, "🔄 Синхронизация сети...", Toast.LENGTH_SHORT).show()
            },
            onClearCache = {
                viewModel.clearPeers(context)
                Toast.makeText(context, "🧹 Кэш устройств очищен!", Toast.LENGTH_SHORT).show()
            },
            onCheckUpdate = checkUpdate,
        )
        Screen.Diagnostics -> DiagnosticsScreen(onBack = { currentScreen = Screen.Main })
        Screen.Settings -> SettingsScreen(
            onBack = { currentScreen = Screen.Main },
            currentTheme = appTheme,
            dynamicColorEnabled = dynamicColorEnabled,
            onThemeChange = onThemeChange,
            onDynamicColorChange = onDynamicColorChange,
            onCheckUpdate = checkUpdate,
        )
    }

    // ── Update Dialog ─────────────────────────────────────────────────────────
    UpdateDialog(
        state = updateState,
        onDownload = { version, url, size ->
            coroutineScope.launch {
                AppUpdateManager.downloadAndInstall(context, version, url, size)
            }
        },
        onCancelDownload = { AppUpdateManager.cancelDownload() },
        onDismiss = { AppUpdateManager.dismiss() }
    )

    // ── Profile BottomSheet ───────────────────────────────────────────────────
    if (showProfileSheet) {
        ProfileBottomSheet(
            profiles = uiState.profiles,
            onDismiss = { showProfileSheet = false },
            onSwitch  = { id ->
                showProfileSheet = false
                viewModel.switchProfile(id, context)
            },
            onEdit = { prof ->
                showProfileSheet = false
                showProfileEdit = ProfileEditMode.Edit(prof)
            },
            onShareQR = { id ->
                showProfileSheet = false
                val uri = viewModel.exportProfileUri(id)
                activity?.shareQRPayload(uri)
            },
            onCreate = {
                showProfileSheet = false
                showProfileEdit = ProfileEditMode.Create
            },
            onImport = {
                showProfileSheet = false
                showImportDialog = true
            },
            onDelete = { id ->
                showProfileSheet = false
                viewModel.deleteProfile(context, id)
            },
        )
    }

    // ── Profile edit/create dialog ────────────────────────────────────────────
    showProfileEdit?.let { mode ->
        ProfileEditDialog(
            mode = mode,
            onDismiss = { showProfileEdit = null },
            onSave = { name, broker, topic, tgToken, tgChat, tgProxy ->
                when (mode) {
                    is ProfileEditMode.Create -> viewModel.createProfile(
                        context, name, broker, topic, tgToken, tgChat, tgProxy
                    )
                    is ProfileEditMode.Edit -> viewModel.updateProfile(
                        context, mode.profile.id, name, broker, topic, tgToken, tgChat, tgProxy
                    )
                }
                showProfileEdit = null
            }
        )
    }

    // ── Import dialog ──────────────────────────────────────────────────────────
    if (showImportDialog) {
        var importUri by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            title = { Text("Импорт профиля") },
            text = {
                OutlinedTextField(
                    value = importUri,
                    onValueChange = { importUri = it },
                    label = { Text("natbypass://profile?... или JSON") },
                    minLines = 2,
                )
            },
            confirmButton = {
                Button(onClick = {
                    val ok = viewModel.importProfile(context, importUri.trim())
                    if (ok) Toast.makeText(context, "Профиль импортирован", Toast.LENGTH_SHORT).show()
                    else Toast.makeText(context, "Ошибка импорта", Toast.LENGTH_LONG).show()
                    showImportDialog = false
                }) { Text("Импортировать") }
            },
            dismissButton = {
                OutlinedButton(onClick = { showImportDialog = false }) { Text("Отмена") }
            }
        )
    }
}

// ── Profile edit/create dialog composable ─────────────────────────────────────
sealed class ProfileEditMode {
    object Create : ProfileEditMode()
    data class Edit(val profile: org.natbypass.app.ui.ProfileUiModel) : ProfileEditMode()
}

@Composable
private fun ProfileEditDialog(
    mode: ProfileEditMode,
    onDismiss: () -> Unit,
    onSave: (String, String, String, String, Long, String) -> Unit,
) {
    val initial = (mode as? ProfileEditMode.Edit)?.profile
    var name    by remember { mutableStateOf(initial?.name ?: "") }
    var broker  by remember { mutableStateOf(initial?.mqttBroker ?: "tcp://broker.emqx.io:1883") }
    var topic   by remember { mutableStateOf(initial?.mqttTopic ?: "") }
    var tgToken by remember { mutableStateOf(initial?.tgToken ?: "") }
    var tgChat  by remember { mutableStateOf(initial?.tgChat?.takeIf { it > 0 }?.toString() ?: "") }
    var tgProxy by remember { mutableStateOf(initial?.tgProxy ?: "") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (mode is ProfileEditMode.Create) "Новая сеть" else "Редактировать сеть") },
        text = {
            androidx.compose.foundation.layout.Column(
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Название") }, singleLine = true)
                OutlinedTextField(value = topic, onValueChange = { topic = it }, label = { Text("MQTT Топик") }, singleLine = true)
                OutlinedTextField(value = broker, onValueChange = { broker = it }, label = { Text("MQTT Брокер") }, singleLine = true)
                OutlinedTextField(value = tgToken, onValueChange = { tgToken = it }, label = { Text("TG Bot Token") }, singleLine = true)
                OutlinedTextField(value = tgChat, onValueChange = { tgChat = it }, label = { Text("TG Chat ID") }, singleLine = true)
                OutlinedTextField(value = tgProxy, onValueChange = { tgProxy = it }, label = { Text("TG Прокси") }, singleLine = true)
            }
        },
        confirmButton = {
            Button(onClick = {
                onSave(name.trim(), broker.trim(), topic.trim(), tgToken.trim(), tgChat.toLongOrNull() ?: 0L, tgProxy.trim())
            }) { Text("Сохранить") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        }
    )
}

private sealed class Screen {
    object Main : Screen()
    object Diagnostics : Screen()
    object Settings : Screen()
}
