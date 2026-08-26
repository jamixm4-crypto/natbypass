package org.natbypass.app.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import org.natbypass.app.ui.compose.DiagnosticsScreen
import org.natbypass.app.ui.compose.NatBypassTheme

class DiagnosticsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            NatBypassTheme {
                DiagnosticsScreen(onBack = { finish() })
            }
        }
    }
}
