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
import org.natbypass.app.ui.PeerUiModel

// ── Status dot colors ─────────────────────────────────────────────────────────
@Composable
private fun statusColor(channelType: String): Color {
    val colors = MaterialTheme.natColors
    return when (channelType) {
        "p2p"    -> colors.success
        "relay"  -> colors.warning
        else     -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.35f)
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

// ── Channel label ─────────────────────────────────────────────────────────────
@Composable
private fun ChannelBadge(channelType: String) {
    val (label, color) = when (channelType) {
        "p2p"   -> Pair("P2P",   MaterialTheme.natColors.success)
        "relay" -> Pair("Relay", MaterialTheme.natColors.warning)
        else    -> Pair("Offline", MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f))
    }
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = color.copy(alpha = 0.15f),
        modifier = Modifier.padding(start = 4.dp)
    ) {
        Text(
            text = label,
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

// ── Main peer card ─────────────────────────────────────────────────────────────
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeerCard(
    peer: PeerUiModel,
    onPing: () -> Unit,
    onCopyIp: () -> Unit,
    onSetExitNode: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showSheet by remember { mutableStateOf(false) }
    val dotColor by animateColorAsState(
        targetValue = statusColor(peer.channelType),
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "dot_color"
    )

    Card(
        onClick = { showSheet = true },
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .padding(12.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Avatar
            PeerAvatar(displayName = peer.displayName)

            Spacer(Modifier.width(12.dp))

            // Name + details
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = peer.displayName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = peer.virtualIp.ifEmpty { "—" },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (peer.isOnline) {
                        ChannelBadge(channelType = peer.channelType)
                    }
                    if (peer.isExitNode) {
                        Spacer(Modifier.width(4.dp))
                        Icon(
                            imageVector = Icons.Filled.Router,
                            contentDescription = "Exit Node",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
            }

            Spacer(Modifier.width(8.dp))

            // RTT + status dot
            Column(horizontalAlignment = Alignment.End) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(dotColor)
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = if (peer.pingMs > 0) "${peer.pingMs}ms" else "—",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
                Text(
                    text = peer.virtualIp,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        PeerActionItem(icon = Icons.Outlined.Speed,   label = "Ping",            onClick = onPing)
        PeerActionItem(icon = Icons.Outlined.ContentCopy, label = "Скопировать IP (${peer.virtualIp})", onClick = onCopyIp)
        PeerActionItem(
            icon = Icons.Outlined.Public,
            label = if (peer.isExitNode) "🌐 Маршрутизировать весь интернет через этот узел" else "Использовать как Exit Node",
            onClick = onSetExitNode,
            tint = if (peer.isExitNode) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
        )
        PeerActionItem(
            icon    = Icons.Outlined.DeleteOutline,
            label   = "Удалить из списка",
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
