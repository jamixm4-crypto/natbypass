package org.natbypass.app.ui

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import org.natbypass.app.ui.compose.AppTheme
import org.natbypass.app.ui.compose.NatBypassTheme
import org.natbypass.app.ui.compose.SettingsScreen
import org.natbypass.app.ui.compose.UpdateDialog
import org.natbypass.app.util.AppUpdateManager

class SettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

        setContent {
            val context = LocalContext.current
            var appTheme by remember {
                mutableStateOf(AppTheme.values().getOrElse(prefs.getInt("app_theme", 0)) { AppTheme.SYSTEM })
            }
            var dynamicColor by remember { mutableStateOf(prefs.getBoolean("dynamic_color", true)) }
            val updateState by AppUpdateManager.updateState.collectAsState()
            val coroutineScope = rememberCoroutineScope()

            NatBypassTheme(appTheme = appTheme, dynamicColor = dynamicColor) {
                SettingsScreen(
                    onBack = { finish() },
                    currentTheme = appTheme,
                    dynamicColorEnabled = dynamicColor,
                    onThemeChange = { t ->
                        appTheme = t
                        prefs.edit().putInt("app_theme", t.ordinal).apply()
                    },
                    onDynamicColorChange = { d ->
                        dynamicColor = d
                        prefs.edit().putBoolean("dynamic_color", d).apply()
                    },
                    onCheckUpdate = {
                        val currentVersion = try {
                            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.3.0"
                        } catch (_: Exception) { "1.3.0" }
                        coroutineScope.launch {
                            AppUpdateManager.checkForUpdates(currentVersion, manual = true)
                        }
                    }
                )

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
            }
        }
    }
}
