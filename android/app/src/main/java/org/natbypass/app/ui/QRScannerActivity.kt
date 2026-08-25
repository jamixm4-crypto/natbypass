package org.natbypass.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import org.natbypass.app.databinding.ActivityQrScannerBinding
import java.io.File
import java.util.concurrent.Executors

class QRScannerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityQrScannerBinding
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private var isScanned = false

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            startCamera()
        } else {
            Toast.makeText(this, "Требуется разрешение на камеру для сканирования QR", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityQrScannerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(binding.cameraPreview.surfaceProvider)
            }

            val imageAnalyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, BarcodeAnalyzer { qrText ->
                        if (!isScanned) {
                            isScanned = true
                            runOnUiThread { handleQRCode(qrText) }
                        }
                    })
                }

            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalyzer)
            } catch (e: Exception) {
                Toast.makeText(this, "Ошибка запуска камеры", Toast.LENGTH_SHORT).show()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun handleQRCode(qrText: String) {
        val prefs = getSharedPreferences("natbypass_prefs", Context.MODE_PRIVATE)

        try {
            when {
                qrText.startsWith("natbypass://profile") -> {
                    val res = org.natbypass.app.util.MobileBridge.importProfileURI(qrText)
                    if (res.startsWith("ERR:")) {
                        Toast.makeText(this, "Ошибка импорта: $res", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this, "✓ Профиль сети успешно импортирован и активирован!", Toast.LENGTH_LONG).show()
                    }
                    finish()
                }
                qrText.startsWith("NatBypass|") -> {
                    val parts = qrText.split("|")
                    val peerName = parts.getOrNull(1) ?: "ПК"
                    val peerIP = parts.getOrNull(2) ?: ""
                    prefs.edit()
                        .putString("last_paired_peer", peerName)
                        .putString("last_paired_ip", peerIP)
                        .apply()
                    Toast.makeText(this, "✓ Успешно привязано к устройству: $peerName ($peerIP)", Toast.LENGTH_LONG).show()
                    finish()
                }
                qrText.startsWith("{") && qrText.endsWith("}") -> {
                    val json = org.json.JSONObject(qrText)
                    val devId = json.optString("device_id", "")
                    val tgToken = json.optString("tg_token", "")
                    val tgChat = json.optString("tg_chat", "")
                    val mqttBroker = json.optString("mqtt_broker", "tcp://broker.emqx.io:1883")
                    val mqttTopic = json.optString("mqtt_topic", "natbypass/mynet/peers")
                    
                    val editor = prefs.edit()
                    if (devId.isNotEmpty()) editor.putString("last_paired_peer", devId)
                    if (tgToken.isNotEmpty()) editor.putString("tg_token", tgToken)
                    if (tgChat.isNotEmpty()) editor.putString("tg_chat", tgChat)
                    if (mqttBroker.isNotEmpty()) editor.putString("mqtt_broker", mqttBroker)
                    if (mqttTopic.isNotEmpty()) editor.putString("mqtt_topic", mqttTopic)
                    editor.apply()

                    val configContent = """
app:
  name: "Android-Device"
  log_level: "info"
  publish_interval: 8
signaling:
  channels:
    - type: "telegram"
      priority: 1
      enabled: ${tgToken.isNotEmpty() && tgChat.isNotEmpty()}
      params:
        token: "$tgToken"
        chat_id: "$tgChat"
    - type: "mqtt"
      priority: 2
      enabled: ${mqttBroker.isNotEmpty()}
      params:
        broker_url: "$mqttBroker"
        topic: "$mqttTopic"
wireguard:
  enabled: true
  listen_port: 51820
  mtu: 1420
""".trimIndent()

                    val configFile = File(filesDir, "config.yaml")
                    configFile.writeText(configContent)

                    org.natbypass.app.util.MobileBridge.restartEngine(configContent)
                    org.natbypass.app.util.MobileBridge.clearPeers()

                    Toast.makeText(this, "✓ Настройки сети применены из QR-кода!", Toast.LENGTH_LONG).show()
                    finish()
                }
                qrText.contains("[Interface]") -> {
                    val confFile = File(filesDir, "imported_wg.conf")
                    confFile.writeText(qrText)
                    Toast.makeText(this, "✓ AmneziaWG/WireGuard конфиг импортирован!", Toast.LENGTH_LONG).show()
                    finish()
                }
                else -> {
                    Toast.makeText(this, "Отсканирован QR: $qrText", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка обработки QR: ${e.message}", Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    private class BarcodeAnalyzer(private val onBarcodeFound: (String) -> Unit) : ImageAnalysis.Analyzer {
        private val scanner = BarcodeScanning.getClient()

        @OptIn(ExperimentalGetImage::class)
        override fun analyze(imageProxy: ImageProxy) {
            val mediaImage = imageProxy.image
            if (mediaImage != null) {
                val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
                scanner.process(image)
                    .addOnSuccessListener { barcodes ->
                        for (barcode in barcodes) {
                            if (barcode.valueType == Barcode.TYPE_TEXT || barcode.valueType == Barcode.TYPE_URL) {
                                barcode.rawValue?.let { onBarcodeFound(it) }
                                break
                            }
                        }
                    }
                    .addOnCompleteListener {
                        imageProxy.close()
                    }
            } else {
                imageProxy.close()
            }
        }
    }
}
