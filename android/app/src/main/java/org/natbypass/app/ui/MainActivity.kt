package org.natbypass.app.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import org.natbypass.app.R
import org.natbypass.app.databinding.ActivityMainBinding
import org.natbypass.app.service.NatBypassVpnService

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
        startStatusPolling()
    }

    private fun setupUI() {
        peersAdapter = PeersAdapter(peersList)
        binding.rvPeers.layoutManager = LinearLayoutManager(this)
        binding.rvPeers.adapter = peersAdapter

        binding.btnVpnToggle.setOnClickListener {
            toggleVpn()
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

    private fun setupAWGSpinner() {
        val modes = arrayOf("🟢 Стандартный WG", "🟡 Обход DPI (AWG 2.0)", "🔴 Макс. скрытность")
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
                try {
                    val mobileClass = Class.forName("mobile.Mobile")
                    val setPresetMethod = mobileClass.getMethod("setAWGPreset", String::class.java)
                    setPresetMethod.invoke(null, presetName)
                } catch (e: Exception) {}
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun toggleVpn() {
        if (NatBypassVpnService.isRunning) {
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
        updateVpnStateUI(true)
    }

    private fun stopVpnService() {
        val intent = Intent(this, NatBypassVpnService::class.java).apply {
            action = NatBypassVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        updateVpnStateUI(false)
    }

    private fun updateVpnStateUI(running: Boolean) {
        if (running) {
            binding.tvStatus.text = getString(R.string.vpn_status_connected)
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.green_bright))
            binding.tvIpAddress.text = "IP в mesh-сети: 10.200.0.100"
            binding.btnVpnToggle.background = ContextCompat.getDrawable(this, R.drawable.bg_vpn_button)
        } else {
            binding.tvStatus.text = getString(R.string.vpn_status_disconnected)
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red_bright))
            binding.tvIpAddress.text = "Нажмите для подключения"
        }
    }

    private fun startStatusPolling() {
        lifecycleScope.launch {
            while (isActive) {
                updateVpnStateUI(NatBypassVpnService.isRunning)
                pollPeers()
                delay(3000)
            }
        }
    }

    private fun pollPeers() {
        try {
            val mobileClass = Class.forName("mobile.Mobile")
            val getPeersMethod = mobileClass.getMethod("getPeersJSON")
            val jsonStr = getPeersMethod.invoke(null) as? String ?: "[]"

            val jsonArray = JSONArray(jsonStr)
            peersList.clear()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val id = if (obj.has("device_id")) obj.getString("device_id") else obj.optString("DeviceID", "Устройство $i")
                val nick = if (obj.has("nickname")) obj.getString("nickname") else obj.optString("Nickname", "")
                val displayName = if (nick.isNotEmpty()) "$nick ($id)" else id
                val vip = if (obj.has("virtual_ip")) obj.getString("virtual_ip") else obj.optString("VirtualIP", "")
                val pubIp = if (obj.has("public_ip")) obj.getString("public_ip") else obj.optString("PublicIP", "—")
                val ipDisplay = if (vip.isNotEmpty()) vip else pubIp
                val stun = if (obj.has("stun_addr")) obj.getString("stun_addr") else obj.optString("STUNAddr", "")
                val isOnline = if (obj.has("online")) obj.getBoolean("online") else obj.optBoolean("Online", true)

                peersList.add(
                    PeerItem(
                        name = displayName,
                        ip = ipDisplay,
                        stun = stun,
                        online = isOnline
                    )
                )
            }
            peersAdapter.notifyDataSetChanged()
        } catch (e: Exception) {
        }
    }

    data class PeerItem(val name: String, val ip: String, val stun: String, val online: Boolean)

    class PeersAdapter(private val items: List<PeerItem>) :
        RecyclerView.Adapter<PeersAdapter.ViewHolder>() {

        class ViewHolder(v: View) : RecyclerView.ViewHolder(v) {
            val tvStatus: TextView = v.findViewById(R.id.tvPeerStatus)
            val tvName: TextView = v.findViewById(R.id.tvPeerName)
            val tvIp: TextView = v.findViewById(R.id.tvPeerIp)
            val tvPing: TextView = v.findViewById(R.id.tvPeerPing)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val v = LayoutInflater.from(parent.context).inflate(R.layout.item_peer, parent, false)
            return ViewHolder(v)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvName.text = item.name
            holder.tvIp.text = if (item.stun.isNotEmpty()) item.stun else item.ip
            holder.tvStatus.text = if (item.online) "🟢" else "🔴"
            holder.tvPing.text = if (item.online) "P2P" else "Офлайн"
        }

        override fun getItemCount() = items.size
    }
}
