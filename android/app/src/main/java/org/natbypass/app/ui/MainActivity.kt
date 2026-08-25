package org.natbypass.app.ui

import android.app.Activity
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.natbypass.app.R
import org.natbypass.app.databinding.ActivityMainBinding
import org.natbypass.app.service.NatBypassVpnService
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val peersList = mutableListOf<PeerItem>()
    private lateinit var peersAdapter: PeersAdapter

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "Разрешение на VPN отклонено", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
        setupAWGSpinner()
        ensureEngineStarted()
        startStatusPolling()
    }

    private fun ensureEngineStarted() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val configFile = File(filesDir, "config.yaml")
                val configYaml = if (configFile.exists()) configFile.readText() else "{}"
                org.natbypass.app.util.MobileBridge.startEngine(configYaml, 0)
            } catch (e: Exception) {}
        }
    }

    private fun setupUI() {
        peersAdapter = PeersAdapter(peersList) { peer ->
            showPeerActionDialog(peer)
        }
        binding.rvPeers.layoutManager = LinearLayoutManager(this)
        binding.rvPeers.adapter = peersAdapter

        binding.btnVpnToggle.setOnClickListener {
            toggleVpn()
        }

        binding.btnCheckUpdate.setOnClickListener {
            checkForUpdates(manual = true)
        }

        binding.btnClearCache.setOnClickListener {
            clearPeersCache()
        }

        binding.btnShareQR.setOnClickListener {
            showShareQRDialog()
        }

        binding.btnScanQR.setOnClickListener {
            startActivity(Intent(this, QRScannerActivity::class.java))
        }

        binding.btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        binding.btnDiagnostics.setOnClickListener {
            startActivity(Intent(this, DiagnosticsActivity::class.java))
        }
    }

    private fun clearPeersCache() {
        org.natbypass.app.util.MobileBridge.clearPeers()
        peersList.clear()
        peersAdapter.notifyDataSetChanged()
        binding.tvPeersCount.text = "0 онлайн"
        binding.tvAvgPing.text = "0 ms"
        Toast.makeText(this, "🧹 Кэш устройств очищен! Сеть пересканируется...", Toast.LENGTH_SHORT).show()
        pollPeers()
    }

    private fun showShareQRDialog() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        val devName = prefs.getString("device_name", android.os.Build.MODEL ?: "Android-Node")
        val ip = binding.tvIpAddress.text.toString().substringBefore(" •").trim()
        val inviteText = "NatBypass|$devName|$ip|https://github.com/jamixm4-crypto/natbypass/releases/latest"

        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        val view = layoutInflater.inflate(R.layout.dialog_qr_share, null)
        dialog.setContentView(view)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val iv = view.findViewById<ImageView>(R.id.ivQrCode)
        val btnCopy = view.findViewById<Button>(R.id.btnCopyLink)
        val btnCancel = view.findViewById<Button>(R.id.btnCancel)

        try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(inviteText, BarcodeFormat.QR_CODE, 512, 512)
            val w = bitMatrix.width
            val h = bitMatrix.height
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565)
            for (x in 0 until w) {
                for (y in 0 until h) {
                    bmp.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
                }
            }
            iv.setImageBitmap(bmp)
        } catch (e: Exception) {}

        btnCopy.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("NatBypass Invite", inviteText))
            Toast.makeText(this, "✓ Ссылка скопирована", Toast.LENGTH_SHORT).show()
            dialog.dismiss()
        }

        btnCancel.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()
    }

    private fun showPeerActionDialog(peer: PeerItem) {
        val options = arrayOf(
            "Скопировать IP (${peer.vip})",
            "Задать имя / В закладки",
            "Использовать как шлюз (Exit Node)",
            "Проверить пинг"
        )

        AlertDialog.Builder(this)
            .setTitle(peer.name)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> {
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("Peer VIP", peer.vip))
                        Toast.makeText(this, "✓ IP ${peer.vip} скопирован", Toast.LENGTH_SHORT).show()
                    }
                    1 -> {
                        val input = EditText(this).apply {
                            hint = "Например: Домашний ПК"
                            setSingleLine()
                        }
                        AlertDialog.Builder(this)
                            .setTitle("Задать имя узлу")
                            .setView(input)
                            .setPositiveButton("Сохранить") { _, _ ->
                                val nick = input.text.toString().trim()
                                val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
                                prefs.edit().putString("nick_${peer.id}", nick).apply()
                                Toast.makeText(this, "✓ Имя сохранено!", Toast.LENGTH_SHORT).show()
                                pollPeers()
                            }
                            .setNegativeButton("Отмена", null)
                            .show()
                    }
                    2 -> {
                        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
                        prefs.edit().putString("selected_exit_node", peer.id).apply()
                        org.natbypass.app.util.MobileBridge.selectExitNode(peer.id)
                        Toast.makeText(this, "✓ Шлюз активирован через ${peer.name}!", Toast.LENGTH_SHORT).show()
                        if (NatBypassVpnService.isRunning) {
                            stopVpnService()
                            lifecycleScope.launch {
                                delay(300)
                                startVpnService()
                            }
                        }
                    }
                    3 -> {
                        Toast.makeText(this, "Задержка: ${peer.ping}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun setupAWGSpinner() {
        val modes = arrayOf("Стандартный WG", "Обход DPI (AWG 2.0)", "Макс. скрытность")
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, modes)
        binding.spAwgMode.adapter = adapter
        binding.spAwgMode.setSelection(1) // Default: Обход DPI

        binding.spAwgMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val presetName = when (position) {
                    0 -> "standard"
                    1 -> "dpi"
                    else -> "stealth"
                }
                org.natbypass.app.util.MobileBridge.setAWGPreset(presetName)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun toggleVpn() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        val isRunning = prefs.getBoolean("vpn_running", false)

        if (isRunning) {
            stopVpnService()
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                vpnPermissionLauncher.launch(vpnIntent)
            } else {
                startVpnService()
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_CONNECT
        }
        ContextCompat.startForegroundService(this, intent)
        updateVpnUI(true)
    }

    private fun stopVpnService() {
        val intent = Intent(this, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        updateVpnUI(false)
    }

    private fun updateVpnUI(connected: Boolean) {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("vpn_running", connected).apply()

        if (connected) {
            binding.tvStatus.text = "ПОДКЛЮЧЕНО"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.green_bright))
            binding.btnVpnToggle.background = ContextCompat.getDrawable(this, R.drawable.bg_vpn_button_connected)
            binding.tvAwgTunnelStatus.text = "AmneziaWG 2.0 • Защищенный туннель активен"
            binding.tvAwgTunnelStatus.setTextColor(ContextCompat.getColor(this, R.color.green_bright))
            binding.awgTunnelBadge.background = ContextCompat.getDrawable(this, R.drawable.bg_chip_green)
        } else {
            binding.tvStatus.text = "ОТКЛЮЧЕНО"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
            binding.btnVpnToggle.background = ContextCompat.getDrawable(this, R.drawable.bg_vpn_button_disconnected)
            binding.tvIpAddress.text = "Нажмите для подключения"
            binding.tvAwgTunnelStatus.text = "AmneziaWG 2.0 • Ожидание подключения"
            binding.tvAwgTunnelStatus.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
            binding.awgTunnelBadge.background = ContextCompat.getDrawable(this, R.drawable.bg_card)
        }
    }

    private fun startStatusPolling() {
        lifecycleScope.launch {
            while (isActive) {
                pollStatus()
                pollPeers()
                delay(2000)
            }
        }
    }

    private fun pollStatus() {
        var pubIp = ""
        var stun = ""
        var vip = "10.200.0.100"
        var curChannel = "MQTT"
        var isRunning = false

        try {
            val jsonStr = org.natbypass.app.util.MobileBridge.getStatusJSON()
            val obj = JSONObject(jsonStr)
            isRunning = obj.optBoolean("running", false)
            pubIp = obj.optString("public_ip", "")
            stun = obj.optString("stun_addr", "")
            vip = obj.optString("virtual_ip", "10.200.0.100")
            curChannel = obj.optString("channel", "MQTT")
        } catch (e: Exception) {
            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            isRunning = prefs.getBoolean("vpn_running", false)
        }

        if (pubIp.isEmpty() || pubIp.contains("...")) {
            lifecycleScope.launch(Dispatchers.IO) {
                val directIp = org.natbypass.app.util.NetworkHelper.getPublicIP()
                val directStun = org.natbypass.app.util.NetworkHelper.getSTUNMappedAddress()
                withContext(Dispatchers.Main) {
                    binding.tvPublicIpAndStun.text = "Внешний IP: $directIp • STUN: ${if (directStun.isNotEmpty()) directStun else "$directIp:51820"}"
                }
            }
        } else {
            binding.tvPublicIpAndStun.text = "Внешний IP: $pubIp • STUN: ${if (stun.isNotEmpty()) stun else "$pubIp:51820"}"
        }

        val vpnActive = isRunning || NatBypassVpnService.isRunning
        if (vpnActive) {
            binding.tvIpAddress.text = "Локальный IP: $vip"
            binding.tvSignalingMode.text = if (curChannel.isNotEmpty()) curChannel else "Direct P2P"
            updateVpnUI(true)
        } else {
            updateVpnUI(false)
        }
    }

    private fun pollPeers() {
        try {
            val jsonStr = org.natbypass.app.util.MobileBridge.getPeersJSON()

            val jsonArray = JSONArray(jsonStr)
            peersList.clear()
            val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
            var onlineCount = 0
            var totalLatency = 0L
            var countWithLatency = 0

            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val id = if (obj.has("device_id")) obj.getString("device_id") else obj.optString("DeviceID", "Устройство $i")
                val savedNick = prefs.getString("nick_$id", "") ?: ""
                val nick = if (savedNick.isNotEmpty()) savedNick else if (obj.has("nickname")) obj.getString("nickname") else obj.optString("Nickname", "")
                val displayName = when {
                    nick.isNotEmpty() && !nick.equals(id, ignoreCase = true) -> "$nick ($id)"
                    nick.isNotEmpty() -> nick
                    else -> id
                }
                val vip = if (obj.has("virtual_ip")) obj.getString("virtual_ip") else obj.optString("VirtualIP", "10.200.0.${i+2}")
                val pubIp = if (obj.has("public_ip")) obj.getString("public_ip") else obj.optString("PublicIP", "")
                val stun = if (obj.has("stun_addr")) obj.getString("stun_addr") else obj.optString("STUNAddr", "")
                val isOnline = if (obj.has("online")) obj.getBoolean("online") else obj.optBoolean("Online", true)
                val isExitNode = obj.optBoolean("is_exit_node", false) || obj.optBoolean("IsExitNode", false)

                val pingMs = obj.optLong("ping_ms", if (isOnline) 14L else 0L)
                if (isOnline) {
                    onlineCount++
                    if (pingMs > 0) {
                        totalLatency += pingMs
                        countWithLatency++
                    }
                }

                var plat = if (obj.has("platform")) obj.getString("platform") else obj.optString("Platform", "")
                if (plat.isEmpty()) {
                    val lower = id.lowercase()
                    plat = when {
                        lower.contains("cloud") || lower.contains("linux") || lower.contains("debian") -> "Linux"
                        lower.contains("keenetic") || lower.contains("jcloud") || lower.contains("router") -> "Keenetic"
                        lower.contains("android") -> "Android"
                        else -> "Windows"
                    }
                }
                val nameWithPlatform = "$displayName [$plat]"
                val stunFormatted = when {
                    stun.isNotEmpty() -> "$vip • $stun"
                    pubIp.isNotEmpty() && pubIp != "—" -> "$vip • $pubIp"
                    else -> "VIP: $vip"
                }

                peersList.add(
                    PeerItem(
                        id = id,
                        name = nameWithPlatform,
                        vip = vip,
                        stun = stunFormatted,
                        online = isOnline,
                        isExitNode = isExitNode,
                        ping = if (isOnline) "${if (pingMs > 0) pingMs else 14} ms" else "Офлайн"
                    )
                )
            }
            peersAdapter.notifyDataSetChanged()
            binding.tvPeersCount.text = "$onlineCount онлайн"
            val avgPing = if (countWithLatency > 0) totalLatency / countWithLatency else if (onlineCount > 0) 14L else 0L
            binding.tvAvgPing.text = "$avgPing ms"

            if (peersList.isEmpty()) {
                binding.tvPeersHeader.text = "Устройства в сети (поиск...)"
            } else {
                binding.tvPeersHeader.text = "Устройства в сети ($onlineCount онлайн)"
            }
        } catch (e: Exception) {}
    }

    data class PeerItem(
        val id: String,
        val name: String,
        val vip: String,
        val stun: String,
        val online: Boolean,
        val isExitNode: Boolean,
        val ping: String
    )

    class PeersAdapter(
        private val items: List<PeerItem>,
        private val onItemClick: (PeerItem) -> Unit
    ) : RecyclerView.Adapter<PeersAdapter.ViewHolder>() {

        class ViewHolder(v: View) : RecyclerView.ViewHolder(v) {
            val tvStatus: TextView = v.findViewById(R.id.tvPeerStatus)
            val tvName: TextView = v.findViewById(R.id.tvPeerName)
            val tvIp: TextView = v.findViewById(R.id.tvPeerIp)
            val tvPing: TextView = v.findViewById(R.id.tvPeerPing)
            val tvExitNodeBadge: TextView = v.findViewById(R.id.tvExitNodeBadge)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val v = LayoutInflater.from(parent.context).inflate(R.layout.item_peer, parent, false)
            return ViewHolder(v)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvName.text = item.name
            holder.tvIp.text = item.stun
            holder.tvStatus.text = if (item.online) "🟢" else "⚪"
            holder.tvPing.text = item.ping
            holder.tvExitNodeBadge.visibility = if (item.isExitNode) View.VISIBLE else View.GONE

            if (item.online) {
                holder.tvPing.background = ContextCompat.getDrawable(holder.itemView.context, R.drawable.bg_chip_blue)
                holder.tvPing.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.text_secondary))
            } else {
                holder.tvPing.background = ContextCompat.getDrawable(holder.itemView.context, R.drawable.bg_card)
                holder.tvPing.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.text_muted))
            }

            holder.itemView.setOnClickListener {
                onItemClick(item)
            }
        }

        override fun getItemCount() = items.size
    }

    private fun checkForUpdates(manual: Boolean) {
        val currentVer = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "1.2.5"
        } catch (e: Exception) {
            "1.2.5"
        }

        if (manual) {
            Toast.makeText(this, "🔍 Проверяем обновления на GitHub...", Toast.LENGTH_SHORT).show()
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val url = URL("https://api.github.com/repos/jamixm4-crypto/natbypass/releases/latest")
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 8000
                conn.readTimeout = 8000
                conn.setRequestProperty("User-Agent", "NatBypass-Android-App")

                if (conn.responseCode == 200) {
                    val response = conn.inputStream.bufferedReader().use { it.readText() }
                    val releaseObj = JSONObject(response)
                    val tagName = releaseObj.optString("tag_name", "").removePrefix("v")
                    val releaseBody = releaseObj.optString("body", "Улучшена стабильность и производительность.")
                    
                    var apkDownloadUrl = ""
                    val assets = releaseObj.optJSONArray("assets")
                    if (assets != null) {
                        for (i in 0 until assets.length()) {
                            val asset = assets.getJSONObject(i)
                            val name = asset.optString("name", "")
                            if (name.endsWith(".apk", ignoreCase = true)) {
                                apkDownloadUrl = asset.optString("browser_download_url", "")
                                break
                            }
                        }
                    }

                    withContext(Dispatchers.Main) {
                        if (isNewerVersion(currentVer, tagName) && apkDownloadUrl.isNotEmpty()) {
                            AlertDialog.Builder(this@MainActivity)
                                .setTitle("🎉 Доступно обновление: v$tagName")
                                .setMessage("Текущая версия: v$currentVer\nНовая версия: v$tagName\n\n$releaseBody")
                                .setPositiveButton("⬇️ Скачать и обновить") { _, _ ->
                                    downloadAndInstallApk(apkDownloadUrl)
                                }
                                .setNegativeButton("Позже", null)
                                .show()
                        } else if (manual && apkDownloadUrl.isNotEmpty()) {
                            AlertDialog.Builder(this@MainActivity)
                                .setTitle("🔄 Свежий билд: v$tagName")
                                .setMessage("У вас уже установлена версия v$currentVer.\n\nХотите загрузить и переустановить самый свежий билд v$tagName с GitHub (со всеми последними обновлениями и исправлениями)?\n\n$releaseBody")
                                .setPositiveButton("⬇️ Скачать свежий билд") { _, _ ->
                                    downloadAndInstallApk(apkDownloadUrl)
                                }
                                .setNegativeButton("Отмена", null)
                                .show()
                        } else if (manual) {
                            Toast.makeText(this@MainActivity, "✓ У вас установлена версия v$currentVer (новых бинарников на GitHub пока нет)", Toast.LENGTH_SHORT).show()
                        } else {
                            // no-op
                        }
                    }
                } else if (manual) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "⚠️ Не удалось связаться с сервером обновлений (Код ${conn.responseCode})", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                if (manual) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Ошибка проверки: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun isNewerVersion(current: String, latest: String): Boolean {
        try {
            val curParts = current.split(".").map { it.toIntOrNull() ?: 0 }
            val latParts = latest.split(".").map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(curParts.size, latParts.size)) {
                val c = curParts.getOrElse(i) { 0 }
                val l = latParts.getOrElse(i) { 0 }
                if (l > c) return true
                if (l < c) return false
            }
        } catch (e: Exception) {}
        return false
    }

    private fun downloadAndInstallApk(apkUrl: String) {
        Toast.makeText(this, "⏳ Загрузка APK обновления...", Toast.LENGTH_LONG).show()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val url = URL(apkUrl)
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 15000
                conn.readTimeout = 30000
                conn.setRequestProperty("User-Agent", "NatBypass-Android-App")

                val apkFile = File(cacheDir, "NatBypass-update.apk")
                if (apkFile.exists()) apkFile.delete()

                conn.inputStream.use { input ->
                    FileOutputStream(apkFile).use { output ->
                        input.copyTo(output)
                    }
                }

                withContext(Dispatchers.Main) {
                    try {
                        val apkUri = FileProvider.getUriForFile(
                            this@MainActivity,
                            "${packageName}.provider",
                            apkFile
                        )
                        val installIntent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(apkUri, "application/vnd.android.package-archive")
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
                        }
                        startActivity(installIntent)
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Ошибка запуска установщика: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Ошибка скачивания: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
