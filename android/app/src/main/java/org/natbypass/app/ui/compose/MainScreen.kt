package org.natbypass.app.ui.compose

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.util.Locale
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
    onImportLink: () -> Unit,
    onSync: () -> Unit,
    onClearCache: () -> Unit,
    onCheckUpdate: () -> Unit,
) {
    var speedDialExpanded by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            var menuExpanded by remember { mutableStateOf(false) }
            TopAppBar(
                title = {
                    val context = LocalContext.current
                    val vName = remember {
                        try {
                            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
                            "v" + (pInfo.versionName ?: "1.6.9")
                        } catch (e: Exception) {
                            "v1.6.9"
                        }
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(end = 4.dp)
                    ) {
                        Text(
                            text = "NatBypass",
                            fontWeight = FontWeight.Bold,
                            fontSize = 19.sp,
                            letterSpacing = (-0.5).sp,
                            maxLines = 1,
                        )
                        Spacer(Modifier.width(6.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                        ) {
                            Text(
                                text = vName,
                                color = MaterialTheme.colorScheme.primary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                maxLines = 1,
                            )
                        }
                        Spacer(Modifier.width(6.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f),
                            modifier = Modifier.clickable { onOpenProfiles() }
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.GroupWork,
                                    contentDescription = "Профиль",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(12.dp)
                                )
                                Spacer(Modifier.width(4.dp))
                                Text(
                                    text = uiState.activeProfileName.ifEmpty { "Основная" },
                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Medium,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                },

                actions = {
                    IconButton(onClick = onOpenDiagnostics) {
                        Icon(Icons.Outlined.Analytics, contentDescription = "Диагностика")
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Outlined.Settings, contentDescription = "Настройки")
                    }
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Filled.MoreVert, contentDescription = "Меню")
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false },
                            modifier = Modifier.background(MaterialTheme.colorScheme.surface)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Проверить обновления") },
                                leadingIcon = { Icon(Icons.Outlined.CloudDownload, contentDescription = null) },
                                onClick = { menuExpanded = false; onCheckUpdate() }
                            )
                            DropdownMenuItem(
                                text = { Text("Синхронизировать сеть") },
                                leadingIcon = { Icon(Icons.Outlined.Sync, contentDescription = null) },
                                onClick = { menuExpanded = false; onSync() }
                            )
                            DropdownMenuItem(
                                text = { Text("Очистить кэш узлов") },
                                leadingIcon = { Icon(Icons.Outlined.CleaningServices, contentDescription = null) },
                                onClick = { menuExpanded = false; onClearCache() }
                            )
                        }
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
                onImportLink = { speedDialExpanded = false; onImportLink() },
                onDiagnostics = { speedDialExpanded = false; onOpenDiagnostics() },
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(bottom = 90.dp),
        ) {
            // ── Connect toggle + status ──────────────────────────────────────
            item {
                ConnectSection(
                    state = uiState.connectionState,
                    avgRttMs = uiState.avgRttMs,
                    onToggle = onToggleVpn,
                )
            }

            // ── My Device Card (VIP + STUN + Traffic) ────────────────────────
            item {
                MyDeviceInfoCard(
                    virtualIp = uiState.virtualIp,
                    stunAddr = uiState.stunAddr,
                    publicIp = uiState.publicIp,
                    natType = uiState.natType,
                    activeChannel = uiState.activeChannel,
                    txBytes = uiState.txBytes,
                    rxBytes = uiState.rxBytes,
                    txSpeedBps = uiState.txSpeedBps,
                    rxSpeedBps = uiState.rxSpeedBps,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }

            // ── Bandwidth & RTT Live Chart ────────────────────────────────────
            if (uiState.connectionState != ConnectionState.DISCONNECTED || uiState.txBytes > 0L || uiState.rxBytes > 0L) {
                item {
                    BandwidthLiveChart(
                        txHistory = uiState.txHistory,
                        rxHistory = uiState.rxHistory,
                        rttHistory = uiState.rttHistory,
                        currentTxSpeed = uiState.txSpeedBps,
                        currentRxSpeed = uiState.rxSpeedBps,
                        avgRttMs = uiState.avgRttMs,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                    )
                }
            }

            // ── Network profile card ─────────────────────────────────────────
            item {
                NetworkCard(

                    profileName = uiState.activeProfileName.ifEmpty { "Основная сеть" },
                    onlinePeers = uiState.onlinePeers,
                    totalPeers  = uiState.totalPeers,
                    onChangeProfile = onOpenProfiles,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
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
                        modifier      = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                    )
                }
            }
        }

        // Dim overlay when speed dial is open
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
            .padding(vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        ConnectToggle(state = state, onClick = onToggle)

        Spacer(Modifier.height(8.dp))

        // Status text
        val (statusText, statusColor) = when (state) {
            ConnectionState.CONNECTED_P2P    -> Pair("Защищено",        MaterialTheme.natColors.success)
            ConnectionState.CONNECTED_RELAY  -> Pair("Резервный канал", MaterialTheme.natColors.warning)
            ConnectionState.CONNECTING       -> Pair("Подключение...",   MaterialTheme.colorScheme.primary)
            ConnectionState.DISCONNECTED     -> Pair("Не подключено",    MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Text(
            text = statusText,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            color = statusColor,
        )

        Spacer(Modifier.height(2.dp))

        // RTT line
        Text(
            text = if (avgRttMs > 0) "RTT: $avgRttMs мс" else "RTT: —",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ── Compact round toggle button ───────────────────────────────────────────────
@Composable
private fun ConnectToggle(state: ConnectionState, onClick: () -> Unit) {
    val isConnected = state == ConnectionState.CONNECTED_P2P || state == ConnectionState.CONNECTED_RELAY
    val isConnecting = state == ConnectionState.CONNECTING

    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val haptic = LocalHapticFeedback.current

    val pressScale by animateFloatAsState(
        targetValue = if (isPressed) 0.88f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        ),
        label = "btn_press_scale"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.55f, targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_alpha"
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = EaseOut),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_scale"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(144.dp)
            .scale(pressScale)
    ) {
        // Glowing animated aura
        if (isConnecting) {
            Box(
                modifier = Modifier
                    .size(136.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = pulseAlpha))
            )
        } else if (isConnected) {
            val auraColor = if (state == ConnectionState.CONNECTED_P2P) MaterialTheme.natColors.success else MaterialTheme.natColors.warning
            Box(
                modifier = Modifier
                    .size(136.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(auraColor.copy(alpha = pulseAlpha * 0.35f))
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
                .size(118.dp)
                .clip(CircleShape)
                .background(buttonColor)
                .clickable(
                    interactionSource = interactionSource,
                    indication = null,
                    onClick = {
                        try {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        } catch (_: Exception) {}
                        onClick()
                    }
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
                modifier = Modifier.size(50.dp)
            )
        }
    }
}


// ── My device info card (Virtual IP + STUN Socket) ────────────────────────────
@Composable
private fun MyDeviceInfoCard(
    virtualIp: String,
    stunAddr: String,
    publicIp: String,
    natType: String,
    activeChannel: String,
    txBytes: Long = 0L,
    rxBytes: Long = 0L,
    txSpeedBps: Long = 0L,
    rxSpeedBps: Long = 0L,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val clipboardManager: ClipboardManager = LocalClipboardManager.current

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)
        ) {
            // Header: Мое устройство + статус
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Outlined.Smartphone,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Мое устройство",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.natColors.success.copy(alpha = 0.15f),
                ) {
                    Text(
                        text = if (activeChannel.isNotEmpty()) activeChannel else "Mesh P2P",
                        color = MaterialTheme.natColors.success,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                    )
                }
            }

            Spacer(Modifier.height(10.dp))

            // Row 1: Виртуальный IP в сети (Mesh IP)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))
                    .clickable {
                        val ipToCopy = virtualIp.ifEmpty { "100.64.200.10" }
                        clipboardManager.setText(AnnotatedString(ipToCopy))
                        Toast.makeText(context, "IP $ipToCopy скопирован", Toast.LENGTH_SHORT).show()
                    }
                    .padding(horizontal = 12.dp, vertical = 9.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = "Статический IP сети (Mesh)",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = virtualIp.ifEmpty { "100.64.200.10" },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "VIP",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.Outlined.ContentCopy,
                        contentDescription = "Копировать IP",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            Spacer(Modifier.height(8.dp))

            // Row 2: STUN сокет (P2P Hole Punching сокет)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))
                    .clickable {
                        if (stunAddr.isNotEmpty()) {
                            clipboardManager.setText(AnnotatedString(stunAddr))
                            Toast.makeText(context, "STUN $stunAddr скопирован", Toast.LENGTH_SHORT).show()
                        }
                    }
                    .padding(horizontal = 12.dp, vertical = 9.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = "STUN P2P Сокет",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = stunAddr.ifEmpty { "Определение..." },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (stunAddr.isNotEmpty()) MaterialTheme.natColors.success else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Icon(
                    imageVector = Icons.Outlined.Bolt,
                    contentDescription = "STUN сокет",
                    tint = if (stunAddr.isNotEmpty()) MaterialTheme.natColors.success else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
            }

            // Row 3: Трафик и скорость (TX / RX)
            if (txBytes > 0L || rxBytes > 0L) {
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val txMb = txBytes / (1024f * 1024f)
                    val rxMb = rxBytes / (1024f * 1024f)
                    val txSpd = if (txSpeedBps >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", txSpeedBps / (1024f * 1024f)) else String.format(Locale.US, "%d KB/s", txSpeedBps / 1024)
                    val rxSpd = if (rxSpeedBps >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", rxSpeedBps / (1024f * 1024f)) else String.format(Locale.US, "%d KB/s", rxSpeedBps / 1024)

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.NorthEast,
                            contentDescription = "Передача",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            text = "TX: ${String.format(Locale.US, "%.1f", txMb)} MB (↑$txSpd)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Medium
                        )
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.SouthWest,
                            contentDescription = "Приём",
                            tint = MaterialTheme.natColors.success,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            text = "RX: ${String.format(Locale.US, "%.1f", rxMb)} MB (↓$rxSpd)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }

            // Дополнительная строка: Публичный IP или NAT тип (если есть)
            if (publicIp.isNotEmpty() || natType.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    if (publicIp.isNotEmpty()) {
                        Text(
                            text = "Внешний IP: $publicIp",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (natType.isNotEmpty()) {
                        Text(
                            text = "NAT: $natType",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
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
        shape = RoundedCornerShape(16.dp),
        onClick = onChangeProfile,
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = profileName,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "Пиров онлайн: $onlinePeers из $totalPeers",
                    style = MaterialTheme.typography.bodySmall,
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
            .padding(vertical = 36.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Outlined.DevicesOther,
            contentDescription = null,
            modifier = Modifier.size(52.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = "Устройства не обнаружены",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
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

// ── Bandwidth & RTT live chart ────────────────────────────────────────────────
@Composable
private fun BandwidthLiveChart(
    txHistory: List<Float>,
    rxHistory: List<Float>,
    rttHistory: List<Float>,
    currentTxSpeed: Long,
    currentRxSpeed: Long,
    avgRttMs: Long,
    modifier: Modifier = Modifier,
) {
    var showLatency by remember { mutableStateOf(false) }

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            // Header with toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (showLatency) Icons.Outlined.Speed else Icons.Outlined.TrendingUp,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = if (showLatency) "Задержка (RTT Latency)" else "Загрузка канала",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                    modifier = Modifier.clickable { showLatency = !showLatency }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (showLatency) "Скорость" else "Пинг (мс)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(4.dp))
                        Icon(
                            imageVector = Icons.Outlined.SwapHoriz,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            // Sub-metrics badges
            if (!showLatency) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    val txSpd = if (currentTxSpeed >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", currentTxSpeed / (1024f * 1024f)) else String.format(Locale.US, "%d KB/s", currentTxSpeed / 1024)
                    val rxSpd = if (currentRxSpeed >= 1024 * 1024) String.format(Locale.US, "%.1f MB/s", currentRxSpeed / (1024f * 1024f)) else String.format(Locale.US, "%d KB/s", currentRxSpeed / 1024)

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
                        Spacer(Modifier.width(4.dp))
                        Text("TX: $txSpd", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(MaterialTheme.natColors.success))
                        Spacer(Modifier.width(4.dp))
                        Text("RX: $rxSpd", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold)
                    }
                }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = if (avgRttMs > 0) "Текущий RTT: $avgRttMs мс" else "RTT: —",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            Spacer(Modifier.height(10.dp))

            // Smooth Canvas Curve
            val primaryColor = MaterialTheme.colorScheme.primary
            val successColor = MaterialTheme.natColors.success
            val gridColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.15f)

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(100.dp)
            ) {
                val w = size.width
                val h = size.height
                if (w <= 0 || h <= 0) return@Canvas

                // Draw background grid lines
                drawLine(gridColor, Offset(0f, h * 0.25f), Offset(w, h * 0.25f), strokeWidth = 1f)
                drawLine(gridColor, Offset(0f, h * 0.50f), Offset(w, h * 0.50f), strokeWidth = 1f)
                drawLine(gridColor, Offset(0f, h * 0.75f), Offset(w, h * 0.75f), strokeWidth = 1f)

                if (showLatency) {
                    val rttPts = if (rttHistory.isNotEmpty()) rttHistory else listOf(0f, 0f)
                    val maxVal = maxOf(rttPts.maxOrNull() ?: 100f, 60f)
                    drawSmoothCurve(rttPts, maxVal, primaryColor, w, h, fillGradient = true)
                } else {
                    val txPts = if (txHistory.isNotEmpty()) txHistory else listOf(0f, 0f)
                    val rxPts = if (rxHistory.isNotEmpty()) rxHistory else listOf(0f, 0f)
                    val maxVal = maxOf((txPts + rxPts).maxOrNull() ?: 1024f, 5000f)

                    drawSmoothCurve(rxPts, maxVal, successColor, w, h, fillGradient = true)
                    drawSmoothCurve(txPts, maxVal, primaryColor, w, h, fillGradient = false)
                }
            }
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawSmoothCurve(
    points: List<Float>,
    maxValue: Float,
    color: Color,
    width: Float,
    height: Float,
    fillGradient: Boolean = false,
) {
    if (points.size < 2) return
    val stepX = width / (points.size - 1).coerceAtLeast(1)

    val path = Path()
    val fillPath = Path()

    val firstY = height - (points[0] / maxValue).coerceIn(0f, 1f) * (height - 10f) - 5f
    path.moveTo(0f, firstY)
    if (fillGradient) {
        fillPath.moveTo(0f, height)
        fillPath.lineTo(0f, firstY)
    }

    for (i in 0 until points.size - 1) {
        val p0x = i * stepX
        val p0y = height - (points[i] / maxValue).coerceIn(0f, 1f) * (height - 10f) - 5f
        val p1x = (i + 1) * stepX
        val p1y = height - (points[i + 1] / maxValue).coerceIn(0f, 1f) * (height - 10f) - 5f

        val cx1 = p0x + (p1x - p0x) / 2f
        val cy1 = p0y
        val cx2 = p0x + (p1x - p0x) / 2f
        val cy2 = p1y

        path.cubicTo(cx1, cy1, cx2, cy2, p1x, p1y)
        if (fillGradient) {
            fillPath.cubicTo(cx1, cy1, cx2, cy2, p1x, p1y)
        }
    }

    if (fillGradient) {
        fillPath.lineTo(width, height)
        fillPath.close()
        drawPath(
            path = fillPath,
            brush = Brush.verticalGradient(
                colors = listOf(color.copy(alpha = 0.30f), color.copy(alpha = 0.02f)),
                startY = 0f,
                endY = height
            )
        )
    }

    drawPath(
        path = path,
        color = color,
        style = Stroke(width = 2.5f, cap = StrokeCap.Round)
    )
}

