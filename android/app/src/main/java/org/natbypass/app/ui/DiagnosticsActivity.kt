package org.natbypass.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.natbypass.app.databinding.ActivityDiagnosticsBinding

class DiagnosticsActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDiagnosticsBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDiagnosticsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnRunDiag.setOnClickListener {
            runDiagnostics()
        }

        binding.btnCopyLogs.setOnClickListener {
            val text = binding.tvDiagLogs.text.toString()
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("NatBypass Logs", text)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "📋 Логи скопированы в буфер обмена!", Toast.LENGTH_SHORT).show()
        }

        binding.btnShareLogs.setOnClickListener {
            val text = binding.tvDiagLogs.text.toString()
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "NatBypass Android Logs")
                putExtra(Intent.EXTRA_TEXT, text)
            }
            startActivity(Intent.createChooser(intent, "Поделиться логами NatBypass"))
        }

        runDiagnostics()
    }

    private fun runDiagnostics() {
        binding.tvDiagLogs.text = "⏳ Сбор диагностических данных и логов ядра...\n"
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                var diagText = ""
                var logsText = ""

                if (org.natbypass.app.util.MobileBridge.isAvailable()) {
                    val jsonStr = org.natbypass.app.util.MobileBridge.getDiagnosticsJSON()
                    diagText = formatDiagnostics(jsonStr)
                    logsText = org.natbypass.app.util.MobileBridge.getLogsText()
                } else {
                    diagText = "⚠️ Нативный модуль ядра GoMobile (mobile.aar) не найден в пакете приложения."
                    logsText = "Убедитесь, что APK собран с модулем gomobile bind."
                }

                """
                === 🩺 ДИАГНОСТИКА СЕТИ ===
                $diagText

                === 📋 ЖУРНАЛ ЯДРА (ПОСЛЕДНИЕ СОБЫТИЯ) ===
                $logsText
                """.trimIndent()
            }
            binding.tvDiagLogs.text = result
        }
    }

    private fun formatDiagnostics(jsonStr: String): String {
        val sb = StringBuilder()
        val obj = JSONObject(jsonStr)

        val items = listOf(
            "internet" to "Интернет",
            "public_ip" to "Публичный IP",
            "stun" to "STUN-сокет (NAT)",
            "channel" to "Сигнальный канал",
            "peers" to "Узлы в сети",
            "nat_type" to "Тип NAT"
        )

        for ((key, label) in items) {
            val item = obj.optJSONObject(key)
            if (item != null) {
                val ok = item.optBoolean("ok", false)
                val icon = if (ok) "✅" else "⚠️"
                val detail = item.optString("detail", "")
                val extra = item.optString("extra", "")
                sb.append("$icon $label: $detail")
                if (extra.isNotEmpty()) sb.append(" ($extra)")
                sb.append("\n\n")
            }
        }
        if (sb.isEmpty()) {
            return "✅ Все сетевые службы NatBypass работают в штатном режиме."
        }
        return sb.toString()
    }
}
