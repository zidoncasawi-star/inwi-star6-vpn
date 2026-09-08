package com.example.vpn

/**
 * أنواع البروتوكولات المدعومة لتهيئة نفق الاتصال
 */
enum class ProxyProtocol(val displayName: String, val defaultPort: Int) {
    VLESS("V2Ray / VLESS (نجمة 6 WebSocket)", 443),
    VMESS("V2Ray / VMess (WebSocket)", 443),
    SSL_SNI_TUNNEL("نفق SSL / SNI (نجمة 6)", 443),
    SSH_TUNNEL("نفق SSH / SOCKS5", 22),
    SOCKS5("SOCKS5 Proxy", 1080),
    HTTP("HTTP / HTTPS Proxy", 8080),
    CUSTOM_TUNNEL("نفق مخصص (Custom Tunnel)", 443)
}

/**
 * قائمة خوادم وثغرات الـ SNI (Bug Hosts) الشائعة لعروض شبكات المغرب (إنوي *6)
 */
data class BugHostInfo(
    val name: String,
    val host: String,
    val category: String
)

val MOROCCAN_STAR_6_BUG_HOSTS = listOf(
    BugHostInfo("Facebook Mobile (مستقر وسريع)", "m.facebook.com", "Facebook"),
    BugHostInfo("WhatsApp Web", "web.whatsapp.com", "WhatsApp"),
    BugHostInfo("Graph Facebook API", "graph.facebook.com", "Facebook"),
    BugHostInfo("Messenger Edge", "edge-chat.facebook.com", "Messenger"),
    BugHostInfo("TikTok Web CDN", "v16-webapp-prime.tiktok.com", "TikTok"),
    BugHostInfo("Instagram CDN", "static.cdninstagram.com", "Instagram")
)

/**
 * نتيجة فحص الاتصال والتشخيص
 */
data class DiagnosticResult(
    val title: String,
    val target: String,
    val isSuccess: Boolean,
    val latencyMs: Long,
    val message: String
)

/**
 * إعدادات تكوين الخادم أو البروكسي
 */
data class VpnProfile(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val protocol: ProxyProtocol,
    val dns: String = "8.8.8.8",
    val mtu: Int = 1500,
    val username: String = "",
    val requiresAuth: Boolean = false,
    val sniHost: String = "",
    val customSniPayload: String = "",
    val uuid: String = "",
    val path: String = "/morocco6",
    val transport: String = "ws"
) {
    val isStar6Profile: Boolean
        get() = sniHost.isNotBlank() || name.contains("*6") || name.contains("نجمة 6") || protocol == ProxyProtocol.VLESS
}

/**
 * حالات تشغيل نفق الـ VPN
 */
enum class VpnStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING
}

/**
 * إحصائيات استهلاك وتدفق البيانات
 */
data class TrafficStats(
    val bytesIn: Long = 0L,
    val bytesOut: Long = 0L,
    val uploadSpeedKbps: Long = 0L,
    val downloadSpeedKbps: Long = 0L,
    val connectedDurationSeconds: Long = 0L
) {
    val totalBytes: Long get() = bytesIn + bytesOut

    fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.2f MB", bytes / (1024.0 * 1024.0))
            else -> String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    fun formatDuration(): String {
        val hrs = connectedDurationSeconds / 3600
        val mins = (connectedDurationSeconds % 3600) / 60
        val secs = connectedDurationSeconds % 60
        return if (hrs > 0) {
            String.format("%02d:%02d:%02d", hrs, mins, secs)
        } else {
            String.format("%02d:%02d", mins, secs)
        }
    }
}
