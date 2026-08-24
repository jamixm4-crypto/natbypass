package org.natbypass.app.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.net.URLEncoder

object NetworkHelper {

    suspend fun getPublicIP(): String = withContext(Dispatchers.IO) {
        val apis = listOf(
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com"
        )
        for (api in apis) {
            try {
                val url = URL(api)
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                if (conn.responseCode == 200) {
                    val ip = conn.inputStream.bufferedReader().readText().trim()
                    if (ip.isNotEmpty() && ip.length <= 45) {
                        return@withContext ip
                    }
                }
            } catch (e: Exception) {}
        }
        "127.0.0.1"
    }

    suspend fun getSTUNMappedAddress(): String = withContext(Dispatchers.IO) {
        val servers = listOf("stun.l.google.com", "stun1.l.google.com", "stun.cloudflare.com")
        for (srv in servers) {
            try {
                val socket = DatagramSocket()
                socket.soTimeout = 2000
                val stunServer = InetAddress.getByName(srv)
                val stunPort = 19302

                // STUN Binding Request (RFC 5389)
                val req = ByteArray(20)
                req[0] = 0x00
                req[1] = 0x01 // Binding Request
                req[2] = 0x00
                req[3] = 0x00 // Length
                req[4] = 0x21
                req[5] = 0x12
                req[6] = 0xA4.toByte()
                req[7] = 0x42.toByte() // Magic Cookie
                for (i in 8 until 20) req[i] = (i * 19).toByte()

                val packet = DatagramPacket(req, req.size, stunServer, stunPort)
                socket.send(packet)

                val respBuf = ByteArray(512)
                val respPacket = DatagramPacket(respBuf, respBuf.size)
                socket.receive(respPacket)
                socket.close()

                var offset = 20
                val len = respPacket.length
                while (offset + 4 <= len) {
                    val attrType = ((respBuf[offset].toInt() and 0xFF) shl 8) or (respBuf[offset + 1].toInt() and 0xFF)
                    val attrLen = ((respBuf[offset + 2].toInt() and 0xFF) shl 8) or (respBuf[offset + 3].toInt() and 0xFF)
                    offset += 4
                    if (offset + attrLen > len) break

                    if (attrType == 0x0020 && attrLen >= 8) { // XOR-MAPPED-ADDRESS
                        val family = respBuf[offset + 1].toInt() and 0xFF
                        if (family == 0x01) { // IPv4
                            val xport = ((respBuf[offset + 2].toInt() and 0xFF) shl 8) or (respBuf[offset + 3].toInt() and 0xFF)
                            val port = xport xor 0x2112
                            val b0 = (respBuf[offset + 4].toInt() and 0xFF) xor 0x21
                            val b1 = (respBuf[offset + 5].toInt() and 0xFF) xor 0x12
                            val b2 = (respBuf[offset + 6].toInt() and 0xFF) xor 0xA4
                            val b3 = (respBuf[offset + 7].toInt() and 0xFF) xor 0x42
                            return@withContext "$b0.$b1.$b2.$b3:$port (Full Cone NAT)"
                        }
                    } else if (attrType == 0x0001 && attrLen >= 8) { // MAPPED-ADDRESS
                        val family = respBuf[offset + 1].toInt() and 0xFF
                        if (family == 0x01) {
                            val port = ((respBuf[offset + 2].toInt() and 0xFF) shl 8) or (respBuf[offset + 3].toInt() and 0xFF)
                            val b0 = respBuf[offset + 4].toInt() and 0xFF
                            val b1 = respBuf[offset + 5].toInt() and 0xFF
                            val b2 = respBuf[offset + 6].toInt() and 0xFF
                            val b3 = respBuf[offset + 7].toInt() and 0xFF
                            return@withContext "$b0.$b1.$b2.$b3:$port (Port Restricted NAT)"
                        }
                    }
                    offset += attrLen
                }
            } catch (e: Exception) {}
        }
        ""
    }

    suspend fun testTelegramHttp(token: String, chatId: String): String = withContext(Dispatchers.IO) {
        try {
            val encodedMsg = URLEncoder.encode("🛸 NatBypass: Тестовый сигнал доставлен!", "UTF-8")
            val url = URL("https://api.telegram.org/bot$token/sendMessage?chat_id=$chatId&text=$encodedMsg")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 6000
            conn.readTimeout = 6000
            val code = conn.responseCode
            if (code == 200) {
                "✓ Бот успешно ответил! Тестовое сообщение доставлено в чат."
            } else {
                val errText = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: "Код $code"
                "Ошибка Telegram API: $errText"
            }
        } catch (e: Exception) {
            "Ошибка соединения с Telegram: ${e.message}"
        }
    }

    suspend fun testMqttTcp(brokerUrl: String, topic: String): String = withContext(Dispatchers.IO) {
        try {
            var cleanUrl = brokerUrl.removePrefix("tcp://").removePrefix("ssl://").removePrefix("mqtt://")
            val parts = cleanUrl.split(":")
            val host = parts[0]
            val port = if (parts.size > 1) parts[1].toIntOrNull() ?: 1883 else 1883

            val socket = Socket()
            socket.connect(InetSocketAddress(host, port), 5000)
            socket.close()
            "✓ Успешное подключение к брокеру $host:$port (топик: $topic)!"
        } catch (e: Exception) {
            "Ошибка подключения к MQTT брокеру: ${e.message}"
        }
    }
}
