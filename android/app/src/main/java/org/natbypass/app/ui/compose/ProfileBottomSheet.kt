package org.natbypass.app.ui.compose

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.natbypass.app.ui.ProfileUiModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileBottomSheet(
    profiles: List<ProfileUiModel>,
    onDismiss: () -> Unit,
    onSwitch: (String) -> Unit,
    onEdit: (ProfileUiModel) -> Unit,
    onShareQR: (String) -> Unit,
    onCreate: () -> Unit,
    onImport: () -> Unit,
    onDelete: (String) -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
    ) {
        Column(modifier = Modifier.padding(bottom = 32.dp)) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Сети",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Row {
                    IconButton(onClick = onImport) {
                        Icon(Icons.Outlined.Download, "Импортировать")
                    }
                    IconButton(onClick = onCreate) {
                        Icon(Icons.Filled.Add, "Создать")
                    }
                }
            }
            HorizontalDivider()

            LazyColumn(modifier = Modifier.heightIn(max = 400.dp)) {
                items(profiles, key = { it.id }) { prof ->
                    ProfileItem(
                        profile = prof,
                        onSwitch  = { onSwitch(prof.id) },
                        onEdit    = { onEdit(prof) },
                        onShareQR = { onShareQR(prof.id) },
                        onDelete  = { onDelete(prof.id) },
                    )
                    HorizontalDivider(modifier = Modifier.padding(start = 72.dp))
                }
            }
        }
    }
}

@Composable
private fun ProfileItem(
    profile: ProfileUiModel,
    onSwitch: () -> Unit,
    onEdit: () -> Unit,
    onShareQR: () -> Unit,
    onDelete: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSwitch)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Active indicator
        if (profile.isActive) {
            Icon(
                imageVector = Icons.Filled.CheckCircle,
                contentDescription = "Активна",
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(32.dp),
            )
        } else {
            Icon(
                imageVector = Icons.Outlined.Circle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
                modifier = Modifier.size(32.dp),
            )
        }
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = profile.name, fontWeight = if (profile.isActive) FontWeight.SemiBold else FontWeight.Normal)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (profile.virtualIp.isNotEmpty()) {
                    Text(
                        text = profile.virtualIp,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.width(6.dp))
                }
                Text(
                    text = profile.mqttTopic.ifEmpty { profile.mqttBroker },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
        }
        // Actions

        IconButton(onClick = onEdit, modifier = Modifier.size(36.dp)) {
            Icon(Icons.Outlined.Edit, "Редактировать", modifier = Modifier.size(18.dp))
        }
        IconButton(onClick = onShareQR, modifier = Modifier.size(36.dp)) {
            Icon(Icons.Outlined.QrCode2, "QR", modifier = Modifier.size(18.dp))
        }
        if (!profile.isActive) {
            IconButton(onClick = onDelete, modifier = Modifier.size(36.dp)) {
                Icon(
                    Icons.Outlined.DeleteOutline, "Удалить",
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}
