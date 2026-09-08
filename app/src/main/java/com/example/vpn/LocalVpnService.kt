package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * خدمة الـ VPN المحلية الرئيسية باستخدام VpnService الرسمي من أندرويد
 * تدعم تشغيل نفق محلي، إشعار دائم، حماية من الإيقاف، وحساب حركة البيانات.
 */
class LocalVpnService : VpnService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetForwarder: PacketForwarder? = null
    private var statsJob: Job? = null

    private var bytesIn = 0L
    private var bytesOut = 0L
    private var durationSeconds = 0L

    companion object {
        const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"
        const val EXTRA_HOST = "EXTRA_HOST"
        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_NAME = "EXTRA_NAME"
        const val EXTRA_PROTOCOL = "EXTRA_PROTOCOL"
        const val EXTRA_SNI_HOST = "EXTRA_SNI_HOST"
        const val EXTRA_DNS = "EXTRA_DNS"
        const val EXTRA_UUID = "EXTRA_UUID"
        const val EXTRA_PATH = "EXTRA_PATH"

        private const val NOTIFICATION_CHANNEL_ID = "vpn_service_channel"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "LocalVpnService"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        when (action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: "187.77.168.45"
                val port = intent.getIntExtra(EXTRA_PORT, 443)
                val name = intent.getStringExtra(EXTRA_NAME) ?: "Inwi6 VPS الخاص بي"
                val protocolStr = intent.getStringExtra(EXTRA_PROTOCOL) ?: ProxyProtocol.VLESS.name
                val sniHost = intent.getStringExtra(EXTRA_SNI_HOST) ?: "m.facebook.com"
                val dns = intent.getStringExtra(EXTRA_DNS) ?: "8.8.8.8"
                val uuid = intent.getStringExtra(EXTRA_UUID) ?: "5ca53c7d-a947-4191-b98d-16ff5cdbd315"
                val path = intent.getStringExtra(EXTRA_PATH) ?: "/morocco6"
                val protocol = try {
                    ProxyProtocol.valueOf(protocolStr)
                } catch (e: Exception) {
                    ProxyProtocol.VLESS
                }

                val profile = VpnProfile(
                    id = "active_profile",
                    name = name,
                    host = host,
                    port = port,
                    protocol = protocol,
                    dns = dns,
                    sniHost = sniHost,
                    uuid = uuid,
                    path = path
                )

                startVpnTunnel(profile)
            }
            ACTION_DISCONNECT -> {
                stopVpnTunnel()
            }
            else -> {
                Log.d(TAG, "أمر غير معروف تم استقباله: $action")
            }
        }

        // START_STICKY يساعد على إبقاء الخدمة تعمل في الخلفية ومنع إيقافها بسهولة من قِبل النظام
        return START_STICKY
    }

    private fun startVpnTunnel(profile: VpnProfile) {
        VpnStateManager.updateStatus(VpnStatus.CONNECTING)
        VpnStateManager.setActiveProfile(profile)
        VpnStateManager.addLog("جارٍ إعداد نفق الـ VPN المحلي...")

        // عرض الإشعار الدائم الفوري المطلوب لخدمات Foreground Service
        startForeground(NOTIFICATION_ID, buildNotification("جارٍ تشغيل النفق...", profile.name))

        serviceScope.launch {
            try {
                // إغلاق أي واجهة قديمة مفتوحة إن وُجدت
                vpnInterface?.close()
                vpnInterface = null

                // بناء واجهة نفق VpnService مع مسارات DNS متعددة لمنع حجب إنوي
                val builder = Builder()
                    .setSession(profile.name)
                    .setMtu(1400) // MTU 1400 لتفادي تقطيع حزم الـ SSL والـ SNI
                    .addAddress("10.1.1.2", 24)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.4.4")
                    .addRoute("0.0.0.0", 0)

                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {}

                // واجهة الحزم المتزامنة لتمرير البيانات دون فقدان
                builder.setBlocking(true)

                // إنشاء واجهة Tun
                val pfd = builder.establish()
                if (pfd == null) {
                    VpnStateManager.addLog("تعذر إنشاء واجهة النفق (ربما لم يوافق المستخدم على إذن الـ VPN)")
                    VpnStateManager.updateStatus(VpnStatus.DISCONNECTED)
                    stopSelf()
                    return@launch
                }

                vpnInterface = pfd
                VpnStateManager.updateStatus(VpnStatus.CONNECTED)
                VpnStateManager.addLog("تم إنشاء نفق الـ VPN بنجاح! متصل بـ: ${profile.host}:${profile.port}")
                if (profile.sniHost.isNotBlank()) {
                    VpnStateManager.addLog("وضع نجمة 6 إنوي (*6): تم تفعيل تزييف الـ SNI (${profile.sniHost}) لتخطي جدار الحظر والوصول إلى google.com")
                }

                // تحديث الإشعار ليعكس الحالة النشطة
                val notifDetail = if (profile.sniHost.isNotBlank()) {
                    "${profile.name} (SNI: ${profile.sniHost})"
                } else {
                    "${profile.name} (${profile.protocol.displayName})"
                }
                updateNotification("النفق متصل بنجاح", notifDetail)

                // بدء محرك تمرير الحزم وتوجيه DNS و VLESS وإحصاء البيانات
                packetForwarder = PacketForwarder(
                    vpnService = this@LocalVpnService,
                    pfd = pfd,
                    profile = profile,
                    onBytesTransferred = { down, up ->
                        bytesIn += down
                        bytesOut += up
                    }
                ).also { it.start() }

                startStatsTracker()

            } catch (e: Exception) {
                Log.e(TAG, "خطأ أثناء تشغيل النفق", e)
                VpnStateManager.addLog("خطأ: ${e.localizedMessage}")
                VpnStateManager.updateStatus(VpnStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * مؤقت دائم لتحديث عداد مدة الاتصال وإحصائيات الاستهلاك وسرعة النقل
     */
    private fun startStatsTracker() {
        statsJob?.cancel()
        durationSeconds = 0L
        bytesIn = 0L
        bytesOut = 0L

        statsJob = serviceScope.launch {
            var prevIn = 0L
            var prevOut = 0L

            while (isActive) {
                delay(1000)
                durationSeconds++

                // احتساب سرعة النقل اللحظية (بالكيلوبت في الثانية)
                val diffIn = (bytesIn - prevIn).coerceAtLeast(0L)
                val diffOut = (bytesOut - prevOut).coerceAtLeast(0L)
                val downloadSpeed = (diffIn * 8) / 1024
                val uploadSpeed = (diffOut * 8) / 1024

                prevIn = bytesIn
                prevOut = bytesOut

                val stats = TrafficStats(
                    bytesIn = bytesIn,
                    bytesOut = bytesOut,
                    uploadSpeedKbps = uploadSpeed,
                    downloadSpeedKbps = downloadSpeed,
                    connectedDurationSeconds = durationSeconds
                )

                VpnStateManager.updateStats(stats)
            }
        }
    }

    private fun stopVpnTunnel() {
        VpnStateManager.updateStatus(VpnStatus.DISCONNECTING)
        VpnStateManager.addLog("جارٍ إيقاف خدمة النفق...")

        serviceScope.launch {
            try {
                packetForwarder?.stop()
                packetForwarder = null
            } catch (_: Exception) {}

            statsJob?.cancel()

            try {
                vpnInterface?.close()
                vpnInterface = null
            } catch (e: Exception) {
                Log.e(TAG, "خطأ أثناء إغلاق واجهة الـ VPN", e)
            }

            VpnStateManager.updateStatus(VpnStatus.DISCONNECTED)
            VpnStateManager.addLog("تم قطع الاتصال بالنفق بنجاح.")

            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "خدمة نفق الـ VPN والبروكسي",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "إشعار دائم لتشغيل خدمة النفق وحماية الاتصال في الخلفية"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, content: String): Notification {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = Intent(this, LocalVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            1,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_custom_logo)
            .setContentTitle(title)
            .setContentText(content)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "قطع الاتصال", disconnectPendingIntent)
            .build()
    }

    private fun updateNotification(title: String, content: String) {
        val notification = buildNotification(title, content)
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            packetForwarder?.stop()
            packetForwarder = null
        } catch (_: Exception) {}
        statsJob?.cancel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        VpnStateManager.updateStatus(VpnStatus.DISCONNECTED)
    }

    override fun onRevoke() {
        super.onRevoke()
        // يتم استدعاؤها في حال ألغى المستخدم صلاحية الـ VPN من إعدادات النظام
        stopVpnTunnel()
    }
}
