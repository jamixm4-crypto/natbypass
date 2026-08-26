package org.natbypass.app.ui.compose

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.natbypass.app.ui.ConnectionState
import org.natbypass.app.ui.MainUiState
import org.natbypass.app.ui.PeerUiModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    uiState: MainUiState,
    onToggleVpn: () -> Unit,
    onPeerPing: (PeerUiModel) -> Unit,
    onPeerCopyIp: (PeerUiModel) -> Unit,
    onPeerSetExitNode: (PeerUiModel) -> Unit,
    onPeerDelete: (PeerUiModel) -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenQRScanner: () -> Unit,
    onShareQR: () -> Unit,
    onSync: () -> Unit,
    onClearCache: () -> Unit,
) {
    var speedDialExpanded by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "NatBypass",
                        fontWeight = FontWeight.Bold,
                        letterSpacing = (-0.5).sp,
                    )
                },
                actions = {
                    IconButton(onClick = onOpenDiagnostics) {
                        Icon(Icons.Outlined.Analytics, contentDescription = "Диагностика")
                    }
                    IconButton(onClick = onSync) {
                        Icon(Icons.Outlined.Sync, contentDescription = "Синхронизация")
                    }
                    IconButton(onClick = onClearCache) {
                        Icon(Icons.Outlined.CleaningServices, contentDescription = "Очистить кэш")
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Outlined.Settings, contentDescription = "Настройки")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                )
            )
        },
        floatingActionButton = {
            SpeedDialFab(
                expanded = speedDialExpanded,
                onToggle = { speedDialExpanded = !speedDialExpanded },
                onScanQR = { speedDialExpanded = false; onOpenQRScanner() },
                onShareQR = { speedDialExpanded = false; onShareQR() },
                onDiagnostics = { speedDialExpanded = false; onOpenDiagnostics() },
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(bottom = 100.dp),
        ) {
            // ── Connect toggle + status ──────────────────────────────────────
            item {
                ConnectSection(
                    state = uiState.connectionState,
                    avgRttMs = uiState.avgRttMs,
                    onToggle = onToggleVpn,
                )
            }

            // ── Network card ─────────────────────────────────────────────────
            item {
                NetworkCard(
                    profileName = uiState.activeProfileName.ifEmpty { "Основная сеть" },
                    onlinePeers = uiState.onlinePeers,
                    totalPeers  = uiState.totalPeers,
                    onChangeProfile = onOpenProfiles,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }

            // ── Quick Actions Row ────────────────────────────────────────────
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    AssistChip(
                        onClick = onSync,
                        label = { Text("Синхронизация", fontSize = 12.sp) },
                        leadingIcon = {
                            Icon(Icons.Outlined.Sync, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                    )
                    AssistChip(
                        onClick = onClearCache,
                        label = { Text("Очистить кэш", fontSize = 12.sp) },
                        leadingIcon = {
                            Icon(Icons.Outlined.CleaningServices, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                    )
                    AssistChip(
                        onClick = onOpenDiagnostics,
                        label = { Text("Диагностика", fontSize = 12.sp) },
                        leadingIcon = {
                            Icon(Icons.Outlined.Analytics, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                    )
                }
            }

            // ── Peers section header ─────────────────────────────────────────
            item {
                Row(
                    modifier = Modifier
                        .padding(horizontal = 20.dp, vertical = 8.dp)
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Устройства в сети",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    if (uiState.peers.isNotEmpty()) {
                        Text(
                            text = "${uiState.onlinePeers} онлайн",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.natColors.success,
                            fontWeight = FontWeight.Medium
                        )
                    } else {
                        Text(
                            text = "Ожидание...",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            // ── Peers list ────────────────────────────────────────────────────
            if (uiState.peers.isEmpty()) {
                item { EmptyPeersPlaceholder() }
            } else {
                items(uiState.peers, key = { it.id }) { peer ->
                    PeerCard(
                        peer = peer,
                        onPing        = { onPeerPing(peer) },
                        onCopyIp      = { onPeerCopyIp(peer) },
                        onSetExitNode = { onPeerSetExitNode(peer) },
                        onDelete      = { onPeerDelete(peer) },
                    )
                }
            }
        }

        // Scrim for speed dial
        if (speedDialExpanded) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.32f))
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) { speedDialExpanded = false }
            )
        }
    }
}

// ── Connect toggle section ─────────────────────────────────────────────────────
@Composable
private fun ConnectSection(
    state: ConnectionState,
    avgRttMs: Long,
    onToggle: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        ConnectToggle(state = state, onClick = onToggle)

        Spacer(Modifier.height(18.dp))

        // Status text
        val (statusText, statusColor) = when (state) {
            ConnectionState.CONNECTED_P2P    -> Pair("Защищено",        MaterialTheme.natColors.success)
            ConnectionState.CONNECTED_RELAY  -> Pair("Резервный канал", MaterialTheme.natColors.warning)
            ConnectionState.CONNECTING       -> Pair("Подключение...",   MaterialTheme.colorScheme.primary)
            ConnectionState.DISCONNECTED     -> Pair("Не подключено",    MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Text(
            text = statusText,
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            color = statusColor,
        )

        Spacer(Modifier.height(4.dp))

        // RTT line
        Text(
            text = if (avgRttMs > 0) "RTT: $avgRttMs мс" else "RTT: —",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ── Big round toggle button ────────────────────────────────────────────────────
@Composable
private fun ConnectToggle(state: ConnectionState, onClick: () -> Unit) {
    val isConnected = state == ConnectionState.CONNECTED_P2P || state == ConnectionState.CONNECTED_RELAY
    val isConnecting = state == ConnectionState.CONNECTING

    val interactionSource = remember { MutableInteractionSource() }
    val scale by animateFloatAsState(
        targetValue = 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMedium
        ),
        label = "btn_scale"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.6f, targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_alpha"
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_scale"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(200.dp)
    ) {
        if (isConnecting) {
            Box(
                modifier = Modifier
                    .size(200.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = pulseAlpha))
            )
        }

        val buttonColor by animateColorAsState(
            targetValue = when (state) {
                ConnectionState.CONNECTED_P2P   -> MaterialTheme.natColors.successContainer
                ConnectionState.CONNECTED_RELAY -> MaterialTheme.natColors.warningContainer
                ConnectionState.CONNECTING      -> MaterialTheme.colorScheme.primary
                ConnectionState.DISCONNECTED    -> MaterialTheme.colorScheme.surfaceVariant
            },
            animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
            label = "btn_color"
        )

        Box(
            modifier = Modifier
                .size(184.dp)
                .scale(scale)
                .clip(CircleShape)
                .background(buttonColor)
                .clickable(
                    interactionSource = interactionSource,
                    indication = null,
                    onClick = onClick
                ),
            contentAlignment = Alignment.Center,
        ) {
            val iconColor = when (state) {
                ConnectionState.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
                else -> Color.White
            }
            Icon(
                imageVector = if (isConnected) Icons.Filled.Check else Icons.Filled.PowerSettingsNew,
                contentDescription = "Переключить VPN",
                tint = iconColor,
                modifier = Modifier.size(72.dp)
            )
        }
    }
}

// ── Network profile card ──────────────────────────────────────────────────────
@Composable
private fun NetworkCard(
    profileName: String,
    onlinePeers: Int,
    totalPeers: Int,
    onChangeProfile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        onClick = onChangeProfile,
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = profileName,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Пиров онлайн: $onlinePeers из $totalPeers",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                imageVector = Icons.Filled.KeyboardArrowDown,
                contentDescription = "Сменить профиль",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ── Empty peers placeholder ───────────────────────────────────────────────────
@Composable
private fun EmptyPeersPlaceholder() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Outlined.DevicesOther,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = "Устройства не обнаружены",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyLarge,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = "Добавьте устройство через QR или\nподождите автоматического обнаружения",
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
            style = MaterialTheme.typography.bodySmall,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}
