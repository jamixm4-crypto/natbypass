package org.natbypass.app.ui.compose

import androidx.compose.animation.*
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SpeedDialFab(
    expanded: Boolean,
    onToggle: () -> Unit,
    onScanQR: () -> Unit,
    onShareQR: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    Column(horizontalAlignment = Alignment.End) {
        // Mini FABs
        AnimatedVisibility(
            visible = expanded,
            enter = slideInVertically(
                animationSpec = spring(stiffness = Spring.StiffnessMediumLow)
            ) { it } + fadeIn(),
            exit  = slideOutVertically(
                animationSpec = spring(stiffness = Spring.StiffnessMediumLow)
            ) { it } + fadeOut(),
        ) {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SpeedDialItem(
                    icon  = Icons.Outlined.QrCodeScanner,
                    label = "Сканировать QR",
                    onClick = onScanQR,
                )
                SpeedDialItem(
                    icon  = Icons.Outlined.Share,
                    label = "Поделиться QR",
                    onClick = onShareQR,
                )
                SpeedDialItem(
                    icon  = Icons.Outlined.Analytics,
                    label = "Диагностика",
                    onClick = onDiagnostics,
                )
                Spacer(Modifier.height(4.dp))
            }
        }

        // Main FAB
        FloatingActionButton(
            onClick = onToggle,
            containerColor = MaterialTheme.colorScheme.primary,
        ) {
            AnimatedContent(
                targetState = expanded,
                transitionSpec = {
                    scaleIn() + fadeIn() togetherWith scaleOut() + fadeOut()
                },
                label = "fab_icon"
            ) { isExpanded ->
                Icon(
                    imageVector = if (isExpanded) Icons.Filled.Close else Icons.Filled.Add,
                    contentDescription = if (isExpanded) "Закрыть" else "Добавить",
                )
            }
        }
    }
}

@Composable
private fun SpeedDialItem(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
) {
    val interactionSource = remember { MutableInteractionSource() }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.End,
        modifier = Modifier
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                onClick = onClick,
            )
            .padding(vertical = 2.dp),
    ) {
        // Label chip - fully clickable
        Surface(
            shape = MaterialTheme.shapes.small,
            color = MaterialTheme.colorScheme.surfaceVariant,
            tonalElevation = 4.dp,
            shadowElevation = 4.dp,
            onClick = onClick,
        ) {
            Text(
                text = label,
                fontWeight = FontWeight.Medium,
                fontSize = 13.sp,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(12.dp))
        // Mini FAB
        SmallFloatingActionButton(
            onClick = onClick,
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}
