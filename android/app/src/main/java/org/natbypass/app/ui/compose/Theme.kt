package org.natbypass.app.ui.compose

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// ── Custom semantic colors (not part of M3 colorScheme) ──────────────────────
data class NatBypassColors(
    val success: Color,
    val successContainer: Color,
    val warning: Color,
    val warningContainer: Color,
)

val LocalNatBypassColors = staticCompositionLocalOf {
    NatBypassColors(
        success        = Color(0xFF4ADE80),
        successContainer = Color(0xFF16A34A),
        warning        = Color(0xFFFB923C),
        warningContainer = Color(0xFFEA580C),
    )
}

// ── Fallback palette for Android < 12 ────────────────────────────────────────
private val LightColorScheme = lightColorScheme(
    primary          = Color(0xFF2563EB),
    onPrimary        = Color.White,
    primaryContainer = Color(0xFFDBEAFE),
    secondary        = Color(0xFF0891B2),
    onSecondary      = Color.White,
    background       = Color(0xFFFAFAFA),
    surface          = Color(0xFFFFFFFF),
    surfaceVariant   = Color(0xFFF1F5F9),
    onSurfaceVariant = Color(0xFF64748B),
    error            = Color(0xFFDC2626),
)

private val DarkColorScheme = darkColorScheme(
    primary          = Color(0xFF60A5FA),
    onPrimary        = Color(0xFF1E3A5F),
    primaryContainer = Color(0xFF1D4ED8),
    secondary        = Color(0xFF22D3EE),
    onSecondary      = Color(0xFF0C4A6E),
    background       = Color(0xFF0F172A),   // slate-900
    surface          = Color(0xFF1E293B),   // slate-800
    surfaceVariant   = Color(0xFF334155),   // slate-700
    onSurfaceVariant = Color(0xFF94A3B8),
    error            = Color(0xFFF87171),
)

enum class AppTheme { SYSTEM, LIGHT, DARK }

@Composable
fun NatBypassTheme(
    appTheme: AppTheme = AppTheme.SYSTEM,
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val darkTheme = when (appTheme) {
        AppTheme.DARK  -> true
        AppTheme.LIGHT -> false
        AppTheme.SYSTEM -> isSystemInDarkTheme()
    }

    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else      -> LightColorScheme
    }

    val natBypassColors = NatBypassColors(
        success         = Color(0xFF4ADE80),
        successContainer= Color(0xFF16A34A),
        warning         = Color(0xFFFB923C),
        warningContainer= Color(0xFFEA580C),
    )

    CompositionLocalProvider(LocalNatBypassColors provides natBypassColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography  = Typography(),
            content     = content
        )
    }
}

/** Shorthand to access custom NatBypass colors in any composable */
val MaterialTheme.natColors: NatBypassColors
    @Composable get() = LocalNatBypassColors.current
