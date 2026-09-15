package org.natbypass.app.ui.compose

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import org.natbypass.app.ui.PeerUiModel

// ── Status dot colors ─────────────────────────────────────────────────────────
@Composable
private fun statusColor(channelType: String, transport: String = ""): Color {
    val colors = MaterialTheme.natColors
    return when {
        transport == "tls" || channelType == "tcp" -> Color(0xFFA855F7) // Purple for Direct TCP (ShadowTLS)
        transport == "awg" || channelType == "p2p" -> colors.success   // Emerald for Direct UDP (AWG)
        channelType == "relay"                     -> colors.warning   // Amber for Relay
        else                                       -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.35f)
    }
}

// ── Avatar circle ─────────────────────────────────────────────────────────────
@Composable
private fun PeerAvatar(displayName: String, modifier: Modifier = Modifier) {
    val letter = displayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
    val seed = displayName.hashCode()
    val hue = ((seed and 0xFFFFFF) % 360).toFloat()
    val avatarColor = Color.hsl(hue, 0.45f, 0.42f)

    Box(
        modifier = modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(avatarColor),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text  = letter,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp,
        )
    }
}

// ── Transport badge (AWG / TLS / Relay) ───────────────────────────────────────
// ── Transport badge (AWG / TLS / Relay) ───────────────────────────────────────
@Composable
private fun TransportBadge(transport: String, channelType: String, detail: String = "") {
    val (label, color) = when {
        transport == "tls" || channelType == "tcp" -> Pair("TLS", Color(0xFFA855F7))
        transport == "awg" || channelType == "p2p" -> Pair("AWG", MaterialTheme.natColors.success)
        channelType == "relay" && detail.startsWith("Релей через") -> {
            val via = detail.removePrefix("Релей через").trim().take(12)
            Pair("🛡️ $via", MaterialTheme.natColors.warning)
        }
        channelType == "relay"                     -> Pair("Relay", MaterialTheme.natColors.warning)
        else                                       -> Pair("Offline", MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f))
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
    ) {
        Text(
            text = label,
            color = color,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.5.dp)
        )
    }
}

// ── Version badge ─────────────────────────────────────────────────────────────
@Composable
private fun VersionBadge(version: String) {
    if (version.isEmpty()) return
    val clean = if (version.startsWith("v", ignoreCase = true)) version else "v$version"
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = MaterialTheme.colorScheme.secondary.copy(alpha = 0.12f),
    ) {
        Text(
            text = clean,
            color = MaterialTheme.colorScheme.secondary,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.5.dp)
        )
    }
}

// ── Exit node badge ───────────────────────────────────────────────────────────
@Composable
private fun ExitNodeBadge(isSelected: Boolean) {
    val activeColor = Color(0xFF22C55E)
    val color = if (isSelected) activeColor else MaterialTheme.colorScheme.primary
    val bgColor = if (isSelected) activeColor.copy(alpha = 0.18f) else color.copy(alpha = 0.12f)
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = bgColor,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.5.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.Public,
                contentDescription = "Exit Node",
                tint = color,
                modifier = Modifier.size(11.dp)
            )
            Spacer(Modifier.width(3.dp))
            Text(
                text = if (isSelected) "ШЛЮЗ (АКТИВЕН)" else "ШЛЮЗ",
                color = color,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

// ── Subnet route badge ────────────────────────────────────────────────────────
@Composable
private fun SubnetBadge(subnet: String) {
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = Color(0xFF38BDF8).copy(alpha = 0.15f),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.5.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.Home,
                contentDescription = "Subnet",
                tint = Color(0xFF0284C7),
                modifier = Modifier.size(11.dp)
            )
            Spacer(Modifier.width(3.dp))
            Text(
                text = subnet,
                color = Color(0xFF0284C7),
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

// ── Main peer card ─────────────────────────────────────────────────────────────
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun PeerCard(
    peer: PeerUiModel,
    onPing: () -> Unit,
    onCopyIp: () -> Unit,
    onConnectTCP: () -> Unit = {},
    onSetExitNode: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showSheet by remember { mutableStateOf(false) }
    val haptic = LocalHapticFeedback.current
    val dotColor by animateColorAsState(
        targetValue = statusColor(peer.channelType, peer.transport),
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "dot_color"
    )

    Card(
        onClick = {
            try { haptic.performHapticFeedback(HapticFeedbackType.LongPress) } catch (_: Exception) {}
            showSheet = true
        },
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.Top,
        ) {
            // Avatar
            PeerAvatar(
                displayName = peer.displayName,
                modifier = Modifier.padding(top = 2.dp)
            )

            Spacer(Modifier.width(12.dp))

            // Main info column
            Column(modifier = Modifier.weight(1f)) {
                // Line 1: Name + Status/Ping
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = peer.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    Spacer(Modifier.width(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(dotColor)
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = when {
                                !peer.isOnline -> "офлайн"
                                peer.pingMs > 0 -> "${peer.pingMs} ms"
                                else -> "онлайн"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = if (peer.isOnline) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.outline,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }

                Spacer(Modifier.height(4.dp))

                // Line 2: Virtual IP & Transport & Version
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f, fill = false)
                    ) {
                        Text(
                            text = peer.virtualIp.ifEmpty { "—" },
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (peer.isOnline) {
                            Spacer(Modifier.width(6.dp))
                            TransportBadge(transport = peer.transport, channelType = peer.channelType, detail = peer.transportDetail)
                        }
                    }
                    if (peer.version.isNotEmpty()) {
                        Spacer(Modifier.width(8.dp))
                        VersionBadge(version = peer.version)
                    }
                }

                // Line 3: Extra Badges (Exit Node, Subnets) - only if present
                val hasExtraBadges = peer.isExitNode || peer.advertisedRoutes.isNotEmpty()
                if (hasExtraBadges) {
                    Spacer(Modifier.height(6.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (peer.isExitNode) {
                            ExitNodeBadge(isSelected = peer.isSelectedExitNode)
                        }
                        peer.advertisedRoutes.forEach { subnet ->
                            SubnetBadge(subnet = subnet)
                        }
                    }
                }
            }
        }
    }

    // ── Actions BottomSheet ───────────────────────────────────────────────────
    if (showSheet) {
        ModalBottomSheet(
            onDismissRequest = { showSheet = false },
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        ) {
            PeerActionsContent(
                peer = peer,
                onPing = { showSheet = false; onPing() },
                onCopyIp = { showSheet = false; onCopyIp() },
                onConnectTCP = { showSheet = false; onConnectTCP() },
                onSetExitNode = { showSheet = false; onSetExitNode() },
                onDelete = { showSheet = false; onDelete() },
            )
        }
    }
}

@Composable
private fun PeerActionsContent(
    peer: PeerUiModel,
    onPing: () -> Unit,
    onCopyIp: () -> Unit,
    onConnectTCP: () -> Unit,
    onSetExitNode: () -> Unit,
    onDelete: () -> Unit,
) {
    Column(modifier = Modifier.padding(bottom = 24.dp)) {
        // Header
        Row(
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            PeerAvatar(displayName = peer.displayName, modifier = Modifier.size(36.dp))
            Spacer(Modifier.width(12.dp))
            Column {
                Text(text = peer.displayName, fontWeight = FontWeight.SemiBold)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = peer.virtualIp.ifEmpty { "—" },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = "• " + peer.transportDetail.ifEmpty { peer.transport.uppercase() },
                        style = MaterialTheme.typography.bodySmall,
                        color = when {
                            peer.transport == "tls" || peer.channelType == "tcp" -> Color(0xFFA855F7)
                            peer.transport == "awg" || peer.channelType == "p2p" -> MaterialTheme.natColors.success
                            peer.channelType == "relay"                          -> MaterialTheme.natColors.warning
                            else                                                 -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        fontWeight = FontWeight.Medium
                    )
                }
                if (peer.version.isNotEmpty() || peer.platform.isNotEmpty()) {
                    Spacer(Modifier.height(3.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (peer.version.isNotEmpty()) {
                            val vClean = if (peer.version.startsWith("v", ignoreCase = true)) peer.version else "v${peer.version}"
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = MaterialTheme.colorScheme.secondary.copy(alpha = 0.12f),
                            ) {
                                Text(
                                    text = vClean,
                                    color = MaterialTheme.colorScheme.secondary,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
                                )
                            }
                        }
                        if (peer.platform.isNotEmpty()) {
                            if (peer.version.isNotEmpty()) Spacer(Modifier.width(6.dp))
                            Text(
                                text = "• " + peer.platform,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        PeerActionItem(icon = Icons.Outlined.Speed,   label = "⚡ Проверить пинг (Ping)", onClick = onPing)
        PeerActionItem(icon = Icons.Outlined.ContentCopy, label = "📋 Скопировать IP (${peer.virtualIp})", onClick = onCopyIp)
        PeerActionItem(icon = Icons.Outlined.Bolt, label = "⚡ Подключиться по Direct TCP (ShadowTLS)", onClick = onConnectTCP, tint = Color(0xFFF59E0B))
        
        // Показываем пункт выхода в интернет ТОЛЬКО если узел действительно является Exit Node
        if (peer.isExitNode) {
            PeerActionItem(
                icon = Icons.Outlined.Public,
                label = if (peer.isSelectedExitNode) "🟢 Отключить интернет-шлюз" else "🌐 Маршрутизировать весь интернет через этот узел",
                onClick = onSetExitNode,
                tint = if (peer.isSelectedExitNode) Color(0xFF22C55E) else MaterialTheme.colorScheme.primary
            )
        }

        // Показываем подсети ТОЛЬКО если узел анонсировал их (информационно, маршрут работает в меш-сети)
        if (peer.advertisedRoutes.isNotEmpty()) {
            val context = LocalContext.current
            peer.advertisedRoutes.forEach { subnet ->
                PeerActionItem(
                    icon = Icons.Outlined.Home,
                    label = "🏠 Маршрут к подсети $subnet (Меш)",
                    onClick = {
                        try {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Subnet", subnet))
                            Toast.makeText(context, "Подсеть $subnet скопирована (доступна через меш-сеть)", Toast.LENGTH_SHORT).show()
                        } catch (_: Throwable) {}
                    },
                    tint = Color(0xFF38BDF8)
                )
            }
        }

        PeerActionItem(
            icon    = Icons.Outlined.DeleteOutline,
            label   = "🗑️ Удалить из списка",
            onClick = onDelete,
            tint    = MaterialTheme.colorScheme.error
        )
    }
}

@Composable
private fun PeerActionItem(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    tint: Color = MaterialTheme.colorScheme.onSurface,
) {
    TextButton(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp),
        contentPadding = PaddingValues(horizontal = 20.dp)
    ) {
        Icon(imageVector = icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(16.dp))
        Text(
            text = label,
            color = tint,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f)
        )
    }
}
