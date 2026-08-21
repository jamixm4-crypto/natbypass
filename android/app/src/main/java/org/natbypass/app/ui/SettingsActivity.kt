package org.natbypass.app.ui

import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
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
    }

    private fun loadSettings() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        binding.etTgToken.setText(prefs.getString("tg_token", ""))
        binding.etTgChat.setText(prefs.getString("tg_chat", ""))
        binding.etMqttBroker.setText(prefs.getString("mqtt_broker", "tcp://mqtt.eclipseprojects.io:1883"))
        binding.etMqttTopic.setText(prefs.getString("mqtt_topic", "natbypass/mynet/peers"))
        binding.swAutoStart.isChecked = prefs.getBoolean("auto_start_on_boot", false)
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("tg_token", binding.etTgToken.text.toString().trim())
            .putString("tg_chat", binding.etTgChat.text.toString().trim())
            .putString("mqtt_broker", binding.etMqttBroker.text.toString().trim())
            .putString("mqtt_topic", binding.etMqttTopic.text.toString().trim())
            .putBoolean("auto_start_on_boot", binding.swAutoStart.isChecked)
            .apply()

        // Создаем config.yaml в приватной папке приложения
        val configContent = """
app:
  name: "NatBypass"
  log_level: "info"
  publish_interval: 60
signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: ${binding.etTgToken.text?.isNotEmpty() == true}
      params:
        token: "${binding.etTgToken.text.toString().trim()}"
        chat_id: "${binding.etTgChat.text.toString().trim()}"
    - type: "mqtt"
      priority: 2
      enabled: true
      params:
        broker_url: "${binding.etMqttBroker.text.toString().trim()}"
        topic: "${binding.etMqttTopic.text.toString().trim()}"
wireguard:
  enabled: true
  listen_port: 51820
  mtu: 1420
""".trimIndent()

        val configFile = File(filesDir, "config.yaml")
        configFile.writeText(configContent)

        Toast.makeText(this, "✓ Настройки успешно сохранены!", Toast.LENGTH_SHORT).show()
        finish()
    }
}
