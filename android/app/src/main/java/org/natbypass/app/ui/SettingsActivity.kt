package org.natbypass.app.ui

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import org.natbypass.app.ui.compose.AppTheme
import org.natbypass.app.ui.compose.NatBypassTheme
import org.natbypass.app.ui.compose.SettingsScreen

class SettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

        setContent {
            var appTheme by remember {
                mutableStateOf(AppTheme.values().getOrElse(prefs.getInt("app_theme", 0)) { AppTheme.SYSTEM })
            }
            var dynamicColor by remember { mutableStateOf(prefs.getBoolean("dynamic_color", true)) }

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
                )
            }
        }
    }
}
