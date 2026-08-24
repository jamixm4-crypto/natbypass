package org.natbypass.app.ui

import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.natbypass.app.databinding.ActivitySettingsBinding
import java.io.File

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        loadSettings()

        binding.btnSaveSettings.setOnClickListener {
            saveSettings()
        }

        binding.btnTestTelegram.setOnClickListener {
            testTelegram()
        }

        binding.btnTestMqtt.setOnClickListener {
            testMQTT()
        }
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        binding.etDeviceName.setText(prefs.getString("device_name", android.os.Build.MODEL ?: "Android-Device"))
        binding.etPublishInterval.setText(prefs.getInt("publish_interval", 8).toString())
        binding.swAutoStart.isChecked = prefs.getBoolean("auto_start_on_boot", false)
        binding.swSaveLogs.isChecked = prefs.getBoolean("save_logs", false)

        binding.etTgToken.setText(prefs.getString("tg_token", ""))
        binding.etTgChat.setText(prefs.getString("tg_chat", ""))
        binding.etTgProxy.setText(prefs.getString("tg_proxy", ""))

        val currentBroker = prefs.getString("mqtt_broker", "tcp://broker.emqx.io:1883") ?: "tcp://broker.emqx.io:1883"
        binding.etMqttBroker.setText(currentBroker)
        binding.etMqttTopic.setText(prefs.getString("mqtt_topic", "natbypass/mynet/peers"))
        binding.etMqttUser.setText(prefs.getString("mqtt_user", ""))
        binding.etMqttPass.setText(prefs.getString("mqtt_pass", ""))

        val brokerPresets = arrayOf(
            "⚡ EMQX Public (Рекомендуется)",
            "⚡ HiveMQ Public",
            "⚡ Eclipse Mosquitto",
            "⚡ Eclipse Foundation",
            "✏️ Свой сервер..."
        )
        val brokerUrls = arrayOf(
            "tcp://broker.emqx.io:1883",
            "tcp://broker.hivemq.com:1883",
            "tcp://test.mosquitto.org:1883",
            "tcp://mqtt.eclipseprojects.io:1883",
            ""
        )
        val spAdapter = android.widget.ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, brokerPresets)
        binding.spMqttBrokerPreset.adapter = spAdapter

        val curIdx = brokerUrls.indexOf(currentBroker)
        if (curIdx >= 0) {
            binding.spMqttBrokerPreset.setSelection(curIdx)
        } else {
            binding.spMqttBrokerPreset.setSelection(4)
        }

        binding.spMqttBrokerPreset.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                if (position < 4 && brokerUrls[position].isNotEmpty()) {
                    binding.etMqttBroker.setText(brokerUrls[position])
                }
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        binding.etWgPort.setText(prefs.getInt("wg_port", 51820).toString())
        binding.etMTU.setText(prefs.getInt("mtu", 1420).toString())
        binding.swDoH.isChecked = prefs.getBoolean("doh_enabled", true)
        binding.swUpnp.isChecked = prefs.getBoolean("upnp_enabled", true)

        binding.swAllowExitNode.isChecked = prefs.getBoolean("allow_exit_node", false)
        binding.etAdvSubnets.setText(prefs.getString("adv_subnets", ""))

        loadLiveNetworkInfo()
    }

    private fun saveSettings() {
        val deviceName = binding.etDeviceName.text.toString().trim()
        val publishInterval = binding.etPublishInterval.text.toString().toIntOrNull() ?: 8
        val tgToken = binding.etTgToken.text.toString().trim()
        val tgChat = binding.etTgChat.text.toString().trim()
        val tgProxy = binding.etTgProxy.text.toString().trim()
        val mqttBroker = binding.etMqttBroker.text.toString().trim()
        val mqttTopic = binding.etMqttTopic.text.toString().trim()
        val mqttUser = binding.etMqttUser.text.toString().trim()
        val mqttPass = binding.etMqttPass.text.toString().trim()
        val wgPort = binding.etWgPort.text.toString().toIntOrNull() ?: 51820
        val mtu = binding.etMTU.text.toString().toIntOrNull() ?: 1420
        val dohEnabled = binding.swDoH.isChecked
        val upnpEnabled = binding.swUpnp.isChecked
        val allowExitNode = binding.swAllowExitNode.isChecked
        val advSubnets = binding.etAdvSubnets.text.toString().trim()

        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("device_name", deviceName)
            .putInt("publish_interval", publishInterval)
            .putBoolean("auto_start_on_boot", binding.swAutoStart.isChecked)
            .putBoolean("save_logs", binding.swSaveLogs.isChecked)
            .putString("tg_token", tgToken)
            .putString("tg_chat", tgChat)
            .putString("tg_proxy", tgProxy)
            .putString("mqtt_broker", mqttBroker)
            .putString("mqtt_topic", mqttTopic)
            .putString("mqtt_user", mqttUser)
            .putString("mqtt_pass", mqttPass)
            .putInt("wg_port", wgPort)
            .putInt("mtu", mtu)
            .putBoolean("doh_enabled", dohEnabled)
            .putBoolean("upnp_enabled", upnpEnabled)
            .putBoolean("allow_exit_node", allowExitNode)
            .putString("adv_subnets", advSubnets)
            .apply()

        // Создаем config.yaml в приватной папке приложения
        val configContent = """
app:
  name: "$deviceName"
  device_name: "$deviceName"
  log_level: "info"
  publish_interval: $publishInterval
  save_logs: ${binding.swSaveLogs.isChecked}
network:
  upnp_enabled: $upnpEnabled
  doh_enabled: $dohEnabled
  allow_exit_node: $allowExitNode
  advertised_subnets:
${if (advSubnets.isNotEmpty()) "    - \"$advSubnets\"" else ""}
signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: ${tgToken.isNotEmpty() && tgChat.isNotEmpty()}
      params:
        token: "$tgToken"
        chat_id: "$tgChat"
        proxy: "$tgProxy"
    - type: "mqtt"
      priority: 2
      enabled: ${mqttBroker.isNotEmpty()}
      params:
        broker_url: "$mqttBroker"
        topic: "$mqttTopic"
        username: "$mqttUser"
        password: "$mqttPass"
wireguard:
  enabled: true
  listen_port: $wgPort
  mtu: $mtu
""".trimIndent()

        val configFile = File(filesDir, "config.yaml")
        configFile.writeText(configContent)

        org.natbypass.app.util.MobileBridge.restartEngine(configContent)

        Toast.makeText(this, "✓ Настройки сохранены и синхронизированы!", Toast.LENGTH_SHORT).show()
        finish()
    }

    private fun loadLiveNetworkInfo() {
        lifecycleScope.launch(Dispatchers.IO) {
            var ip = ""
            var stun = ""
            try {
                val statusJson = org.natbypass.app.util.MobileBridge.getStatusJSON()
                val obj = org.json.JSONObject(statusJson)
                ip = obj.optString("public_ip", "")
                stun = obj.optString("stun_addr", "")
            } catch (e: Exception) {}

            if (ip.isEmpty() || ip.contains("...")) {
                ip = org.natbypass.app.util.NetworkHelper.getPublicIP()
            }
            if (stun.isEmpty() || stun.contains("...")) {
                stun = org.natbypass.app.util.NetworkHelper.getSTUNMappedAddress()
            }

            withContext(Dispatchers.Main) {
                binding.tvCurrentPublicIp.text = "🌐 Внешний IP: ${if (ip.isNotEmpty()) ip else "Определяется..."}"
                binding.tvCurrentStun.text = "📡 STUN-сокет: ${if (stun.isNotEmpty()) stun else "Инициализирован (UDP сокет открыт)"}"
            }
        }
    }

    private fun testTelegram() {
        val token = binding.etTgToken.text.toString().trim()
        val chat = binding.etTgChat.text.toString().trim()
        val proxy = binding.etTgProxy.text.toString().trim()
        if (token.isEmpty() || chat.isEmpty()) {
            Toast.makeText(this, "⚠️ Введите Bot Token и Chat ID", Toast.LENGTH_SHORT).show()
            return
        }
        binding.btnTestTelegram.isEnabled = false
        binding.btnTestTelegram.text = "⏳ Проверяем связь..."
        lifecycleScope.launch(Dispatchers.IO) {
            val r = org.natbypass.app.util.MobileBridge.testTelegram(token, chat, proxy)
            val res = if (r.isNotEmpty()) r else org.natbypass.app.util.NetworkHelper.testTelegramHttp(token, chat)
            withContext(Dispatchers.Main) {
                binding.btnTestTelegram.isEnabled = true
                binding.btnTestTelegram.text = "🧪 Проверить связь с Telegram"
                Toast.makeText(this@SettingsActivity, res, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun testMQTT() {
        val broker = binding.etMqttBroker.text.toString().trim()
        val topic = binding.etMqttTopic.text.toString().trim()
        val user = binding.etMqttUser.text.toString().trim()
        val pass = binding.etMqttPass.text.toString().trim()
        if (broker.isEmpty() || topic.isEmpty()) {
            Toast.makeText(this, "⚠️ Введите Broker URL и топик", Toast.LENGTH_SHORT).show()
            return
        }
        binding.btnTestMqtt.isEnabled = false
        binding.btnTestMqtt.text = "⏳ Проверяем связь..."
        lifecycleScope.launch(Dispatchers.IO) {
            val r = org.natbypass.app.util.MobileBridge.testMQTT(broker, topic, user, pass)
            val res = if (r.isNotEmpty()) r else org.natbypass.app.util.NetworkHelper.testMqttTcp(broker, topic)
            withContext(Dispatchers.Main) {
                binding.btnTestMqtt.isEnabled = true
                binding.btnTestMqtt.text = "🧪 Проверить связь с MQTT брокером"
                Toast.makeText(this@SettingsActivity, res, Toast.LENGTH_LONG).show()
            }
        }
    }
}
