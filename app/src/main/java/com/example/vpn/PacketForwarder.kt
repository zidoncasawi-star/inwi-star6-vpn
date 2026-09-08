package com.example.vpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * محرك تمرير الحزم وتوجيه شبكة أندرويد بالكامل لشبكة إنوي نجمة 6 (Inwi *6) وتخطي الحظر.
 * يعتمد على FakeDNS محلي فوري لتجاوز حظر الـ UDP في شبكة إنوي، وتوجيه حركة TCP بالكامل
 * عبر نفق VLESS + WebSocket مشفر بـ TLS و SNI متوافق 100% مع خوادم Xray.
 */
class PacketForwarder(
    private val vpnService: VpnService,
    private val pfd: ParcelFileDescriptor,
    private val profile: VpnProfile,
    private val onBytesTransferred: (download: Long, upload: Long) -> Unit
) {
    private val TAG = "PacketForwarder"
    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private var isRunning = true

    // جدول تعيين العناوين الافتراضية (FakeDNS IP -> Domain Name)
    private val fakeIpToDomain = ConcurrentHashMap<String, String>()
    private val domainToFakeIp = ConcurrentHashMap<String, String>()
    private val ipCounter = AtomicInteger(1)

    // جدول الاتصالات النشطة
    private val tcpConnections = ConcurrentHashMap<String, TcpConnectionState>()

    // معالج TLS المتساهل مع الشهادات الذاتية مع دعم كامل للـ SNI
    private val sslContext: SSLContext by lazy {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate>? = null
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        })
        SSLContext.getInstance("TLS").apply {
            init(null, trustAll, SecureRandom())
        }
    }

    fun start() {
        scope.launch {
            val inStream = FileInputStream(pfd.fileDescriptor)
            val output = FileOutputStream(pfd.fileDescriptor)
            val packetBuffer = ByteArray(32768)

            VpnStateManager.addLog("✅ بدأ محرك تحويل الحزم وFakeDNS (VLESS WebSocket) على واجهة TUN...")

            try {
                while (isActive && isRunning) {
                    val length = inStream.read(packetBuffer)
                    if (length > 0) {
                        onBytesTransferred(0L, length.toLong())
                        processIpPacket(packetBuffer, length, output)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.d(TAG, "توقف حلقة قراءة الحزم: ${e.message}")
                }
            } finally {
                try { inStream.close() } catch (_: Exception) {}
                try { output.close() } catch (_: Exception) {}
                closeAllConnections()
            }
        }
    }

    /**
     * معالجة حزمة IPv4 الواردة وتوجيهها حسب البروتوكول
     */
    private fun processIpPacket(data: ByteArray, length: Int, output: FileOutputStream) {
        if (length < 20) return
        val version = (data[0].toInt() shr 4) and 0x0F
        if (version != 4) return // IPv4 فقط

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return

        val protocol = data[9].toInt() and 0xFF
        val srcIp = getIpAddress(data, 12)
        val dstIp = getIpAddress(data, 16)

        when (protocol) {
            17 -> handleUdpDns(data, ihl, length, srcIp, dstIp, output)
            6 -> handleTcpStream(data, ihl, length, srcIp, dstIp, output)
            1 -> handleIcmpPing(data, ihl, length, output)
        }
    }

    /**
     * معالج FakeDNS الفوري لحل أي نطاق (google.com, youtube.com, إلخ) دون الاعتماد على UDP إنوي المحظور
     * ورفض بروتوكول QUIC (UDP 443) فورياً حتى يتحول Chrome إلى TCP دون تأخير أو تعليق
     */
    private fun handleUdpDns(
        data: ByteArray,
        ihl: Int,
        totalLength: Int,
        srcIp: String,
        dstIp: String,
        output: FileOutputStream
    ) {
        val udpOffset = ihl
        if (totalLength < udpOffset + 8) return

        val srcPort = getShort(data, udpOffset).toInt() and 0xFFFF
        val dstPort = getShort(data, udpOffset + 2).toInt() and 0xFFFF
        val payloadOffset = udpOffset + 8
        val payloadLength = totalLength - payloadOffset

        if (dstPort != 53) {
            // رفض فوري لـ QUIC / UDP 443 لإجبار المتصفح على استخدام TCP/TLS فوراً
            sendIcmpPortUnreachable(data, ihl, totalLength, output)
            return
        }

        if (payloadLength <= 12) return

        val queryData = data.copyOfRange(payloadOffset, totalLength)
        val transactionId = getShort(queryData, 0)
        val domain = parseDnsDomainName(queryData, 12)

        if (domain.isNotBlank()) {
            // توليد عنوان Fake IP فريد من نطاق 198.18.0.0/16
            val fakeIp = getOrCreateFakeIp(domain)

            // بناء استجابة DNS محلية قياسية فورية
            val dnsResponsePayload = buildDnsResponse(transactionId, queryData, fakeIp)
            val replyPacket = buildUdpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                payload = dnsResponsePayload
            )

            synchronized(output) {
                try {
                    output.write(replyPacket)
                } catch (_: Exception) {}
            }
            onBytesTransferred(replyPacket.size.toLong(), 0L)
        }
    }

    private fun getOrCreateFakeIp(domain: String): String {
        return domainToFakeIp.getOrPut(domain) {
            val id = ipCounter.getAndIncrement() and 0xFFFF
            val b1 = (id shr 8) and 0xFF
            val b2 = id and 0xFF
            val ip = "198.18.$b1.$b2"
            fakeIpToDomain[ip] = domain
            ip
        }
    }

    private fun parseDnsDomainName(dnsData: ByteArray, startOffset: Int): String {
        var offset = startOffset
        val sb = StringBuilder()
        while (offset < dnsData.size) {
            val len = dnsData[offset].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) {
                // تفرع مضغوط
                break
            }
            offset++
            if (offset + len <= dnsData.size) {
                if (sb.isNotEmpty()) sb.append(".")
                sb.append(String(dnsData, offset, len, Charsets.US_ASCII))
                offset += len
            } else {
                break
            }
        }
        return sb.toString()
    }

    private fun buildDnsResponse(txId: Short, queryData: ByteArray, fakeIp: String): ByteArray {
        // البحث عن نهاية قسم السؤال (Question Section)
        var qEnd = 12
        while (qEnd < queryData.size && queryData[qEnd] != 0.toByte()) {
            qEnd += (queryData[qEnd].toInt() and 0xFF) + 1
        }
        qEnd += 1 // تجاوز 00
        qEnd += 4 // تجاوز Type و Class (2+2 = 4)
        if (qEnd > queryData.size) qEnd = queryData.size

        val questionPart = queryData.copyOfRange(0, qEnd)
        val answerHeader = byteArrayOf(
            0xC0.toByte(), 0x0C.toByte(), // Name pointer to question at offset 12
            0x00, 0x01,                   // Type A (Host Address)
            0x00, 0x01,                   // Class IN (Internet)
            0x00, 0x00, 0x00, 0x3C,       // TTL 60 seconds
            0x00, 0x04                    // Data length 4 bytes
        )
        val ipParts = fakeIp.split(".").map { it.toInt().toByte() }.toByteArray()

        val totalLen = questionPart.size + answerHeader.size + 4
        val response = ByteArray(totalLen)
        System.arraycopy(questionPart, 0, response, 0, questionPart.size)

        // تعديل ترويسة DNS: QR=1 (Response), AA=0, TC=0, RD=1, RA=1, RCODE=0 (No Error)
        response[0] = (txId.toInt() shr 8).toByte()
        response[1] = (txId.toInt() and 0xFF).toByte()
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[4] = 0x00 // QDCOUNT = 1
        response[5] = 0x01
        response[6] = 0x00 // ANCOUNT = 1
        response[7] = 0x01
        response[8] = 0x00 // NSCOUNT = 0
        response[9] = 0x00
        response[10] = 0x00 // ARCOUNT = 0
        response[11] = 0x00

        System.arraycopy(answerHeader, 0, response, questionPart.size, answerHeader.size)
        System.arraycopy(ipParts, 0, response, questionPart.size + answerHeader.size, 4)

        return response
    }

    /**
     * معالجة تدفقات TCP (المصافحة المحلية الفورية وتمرير بيانات التطبيقات)
     */
    private fun handleTcpStream(
        data: ByteArray,
        ihl: Int,
        totalLength: Int,
        srcIp: String,
        dstIp: String,
        output: FileOutputStream
    ) {
        val tcpHeaderOffset = ihl
        if (totalLength < tcpHeaderOffset + 20) return

        val srcPort = getShort(data, tcpHeaderOffset).toInt() and 0xFFFF
        val dstPort = getShort(data, tcpHeaderOffset + 2).toInt() and 0xFFFF
        val clientSeq = getInt(data, tcpHeaderOffset + 4)
        val dataOffset = ((data[tcpHeaderOffset + 12].toInt() shr 4) and 0x0F) * 4
        val flags = data[tcpHeaderOffset + 13].toInt() and 0xFF

        val isSyn = (flags and 0x02) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0

        val payloadOffset = tcpHeaderOffset + dataOffset
        val payloadLength = (totalLength - payloadOffset).coerceAtLeast(0)

        val connKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        if (isRst) {
            tcpConnections.remove(connKey)?.close()
            return
        }

        if (isSyn) {
            val targetDomain = fakeIpToDomain[dstIp] ?: ""
            val state = TcpConnectionState(
                srcIp = srcIp,
                srcPort = srcPort,
                dstIp = dstIp,
                dstPort = dstPort,
                targetDomain = targetDomain,
                clientSeq = clientSeq + 1,
                serverSeq = (Math.random() * 1000000).toLong() + 1000
            )
            tcpConnections[connKey] = state

            // إرسال SYN+ACK فوراً لإنهاء المصافحة في نواة أندرويد
            val synAckPacket = buildTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = state.serverSeq,
                ack = state.clientSeq,
                flags = 0x12, // SYN + ACK
                payload = ByteArray(0)
            )
            state.serverSeq++

            synchronized(output) {
                try {
                    output.write(synAckPacket)
                } catch (_: Exception) {}
            }

            // تشغيل النفق الحقيقي مع الخادم
            openOutboundSocket(state, output)
            return
        }

        val conn = tcpConnections[connKey] ?: return

        if (isFin) {
            conn.clientSeq = clientSeq + 1
            val finAck = buildTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = conn.serverSeq,
                ack = conn.clientSeq,
                flags = 0x11, // FIN + ACK
                payload = ByteArray(0)
            )
            synchronized(output) {
                try {
                    output.write(finAck)
                } catch (_: Exception) {}
            }
            conn.close()
            tcpConnections.remove(connKey)
            return
        }

        if (payloadLength > 0) {
            conn.clientSeq = clientSeq + payloadLength
            val payload = data.copyOfRange(payloadOffset, totalLength)

            // إرسال ACK
            val ackPacket = buildTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = conn.serverSeq,
                ack = conn.clientSeq,
                flags = 0x10, // ACK
                payload = ByteArray(0)
            )
            synchronized(output) {
                try {
                    output.write(ackPacket)
                } catch (_: Exception) {}
            }

            // إرسال البيانات عبر النفق
            conn.sendPayload(payload)
        } else {
            // تحديث رقم تسلسل العميل حتى للحزم الخالية من البيانات (Pure ACKs)
            if (clientSeq > conn.clientSeq) {
                conn.clientSeq = clientSeq
            }
        }
    }

    /**
     * الاتصال بخادم الـ VPS مع تغليف WebSocket RFC 6455 الحقيقي لـ VLESS
     */
    private fun openOutboundSocket(state: TcpConnectionState, output: FileOutputStream) {
        scope.launch {
            var rawSocket: Socket? = null
            try {
                rawSocket = Socket()
                vpnService.protect(rawSocket)
                rawSocket.tcpNoDelay = true
                rawSocket.soTimeout = 15000
                rawSocket.connect(InetSocketAddress(profile.host, profile.port), 7000)

                val isTls = (profile.protocol == ProxyProtocol.VLESS && profile.port == 443) || profile.protocol == ProxyProtocol.SSL_SNI_TUNNEL
                val targetSocket: Socket = if (isTls) {
                    val sniHost = if (profile.sniHost.isNotBlank()) profile.sniHost else "m.facebook.com"
                    val ssl = sslContext.socketFactory.createSocket(
                        rawSocket,
                        sniHost,
                        profile.port,
                        true
                    ) as SSLSocket

                    try {
                        val params = ssl.sslParameters
                        try {
                            params.serverNames = listOf(SNIHostName(sniHost))
                        } catch (_: Throwable) {}
                        try {
                            params.applicationProtocols = arrayOf("http/1.1")
                        } catch (_: Throwable) {}
                        ssl.sslParameters = params
                    } catch (_: Throwable) {}

                    try {
                        ssl.startHandshake()
                    } catch (e: Exception) {
                        VpnStateManager.addLog("⚠️ فشلت مصافحة TLS مع ثغرة SNI ($sniHost): ${e.localizedMessage ?: e.javaClass.simpleName} - جرب تبديل البروفايل لثغرة أخرى (WhatsApp أو TikTok)")
                        throw e
                    }
                    ssl
                } else {
                    rawSocket
                }

                state.outboundSocket = targetSocket
                val out = targetSocket.getOutputStream()
                val inStream = targetSocket.getInputStream()

                var isHeaderSent = false

                if (profile.protocol == ProxyProtocol.VLESS) {
                    // 1. مصافحة الـ WebSocket
                    val wsHandshake = buildWebSocketUpgrade(profile)
                    out.write(wsHandshake)
                    out.flush()
                    val statusLine = readHttpResponse(inStream)
                    if (statusLine.contains("101")) {
                        VpnStateManager.addLog("✅ نجحت مصافحة WebSocket (101) مع ${state.targetDomain.ifBlank { state.dstIp }}")
                    } else {
                        VpnStateManager.addLog("⚠️ فشلت مصافحة WebSocket ($statusLine) مع ${state.targetDomain.ifBlank { state.dstIp }}")
                        throw java.io.IOException("WebSocket handshake failed: $statusLine")
                    }

                    // 2. إعداد دالة إرسال البيانات مع ترويسة VLESS لأول إطار
                    state.onSendData = { data ->
                        try {
                            val combinedData = if (!isHeaderSent) {
                                isHeaderSent = true
                                val vlessHeader = buildVlessHeader(profile, state.targetDomain, state.dstIp, state.dstPort)
                                val combined = ByteArray(vlessHeader.size + data.size)
                                System.arraycopy(vlessHeader, 0, combined, 0, vlessHeader.size)
                                System.arraycopy(data, 0, combined, vlessHeader.size, data.size)
                                combined
                            } else {
                                data
                            }
                            val frame = encodeWsBinaryFrame(combinedData)
                            out.write(frame)
                            out.flush()
                        } catch (_: Exception) {}
                    }
                } else {
                    state.onSendData = { data ->
                        try {
                            out.write(data)
                            out.flush()
                        } catch (_: Exception) {}
                    }
                }

                // إرسال البيانات المعلقة المتراكمة من المتصفح
                state.flushPendingData()

                // 3. قراءة استجابة السيرفر وتغذية أندرويد بالبيانات (Download)
                val dataIn = DataInputStream(inStream)
                var isFirstResponse = true

                while (targetSocket.isConnected && !targetSocket.isClosed && isRunning) {
                    var payload = if (profile.protocol == ProxyProtocol.VLESS) {
                        readWsBinaryFrame(dataIn) ?: break
                    } else {
                        val buf = ByteArray(8192)
                        val r = inStream.read(buf)
                        if (r <= 0) break
                        buf.copyOf(r)
                    }

                    // ترويسة استجابة VLESS في أول إطار: [Version(1B) + AddonsLength(1B) + Addons(NB)]
                    if (isFirstResponse && profile.protocol == ProxyProtocol.VLESS) {
                        isFirstResponse = false
                        if (payload.size >= 2) {
                            val addonsLen = payload[1].toInt() and 0xFF
                            val headerLen = 2 + addonsLen
                            if (payload.size > headerLen) {
                                payload = payload.copyOfRange(headerLen, payload.size)
                            } else {
                                continue
                            }
                        }
                    }

                    if (payload.isNotEmpty()) {
                        onBytesTransferred(payload.size.toLong(), 0L)

                        // ضخ البيانات لحزم TCP
                        var offset = 0
                        val chunkSize = 1350
                        while (offset < payload.size) {
                            val count = (payload.size - offset).coerceAtMost(chunkSize)
                            val chunk = payload.copyOfRange(offset, offset + count)

                            val tcpPacket = buildTcpPacket(
                                srcIp = state.dstIp,
                                dstIp = state.srcIp,
                                srcPort = state.dstPort,
                                dstPort = state.srcPort,
                                seq = state.serverSeq,
                                ack = state.clientSeq,
                                flags = 0x18, // PSH + ACK
                                payload = chunk
                            )
                            state.serverSeq += count

                            synchronized(output) {
                                try {
                                    output.write(tcpPacket)
                                } catch (_: Exception) {}
                            }
                            offset += count
                        }
                    }
                }

                // إرسال FIN+ACK لنواة أندرويد لإبلاغ المتصفح بانتهاء تدفق البيانات وعرض الصفحة فوراً
                val finPacket = buildTcpPacket(
                    srcIp = state.dstIp,
                    dstIp = state.srcIp,
                    srcPort = state.dstPort,
                    dstPort = state.srcPort,
                    seq = state.serverSeq,
                    ack = state.clientSeq,
                    flags = 0x11, // FIN + ACK
                    payload = ByteArray(0)
                )
                synchronized(output) {
                    try {
                        output.write(finPacket)
                    } catch (_: Exception) {}
                }
            } catch (e: Exception) {
                if (isRunning) {
                    val msg = e.localizedMessage ?: e.message ?: e.javaClass.simpleName
                    VpnStateManager.addLog("❌ خطأ اتصال بالنفق (${state.targetDomain.ifBlank { state.dstIp }}): $msg")
                }
            } finally {
                state.close()
                tcpConnections.remove("${state.srcIp}:${state.srcPort}->${state.dstIp}:${state.dstPort}")
            }
        }
    }

    /**
     * تغليف مصفوفة البيانات في إطار WebSocket Binary Frame مع Masking Key (RFC 6455)
     */
    private fun encodeWsBinaryFrame(data: ByteArray): ByteArray {
        val maskKey = ByteArray(4).apply { SecureRandom().nextBytes(this) }
        val len = data.size
        val headerLen = when {
            len < 126 -> 2 + 4
            len <= 65535 -> 4 + 4
            else -> 10 + 4
        }
        val frame = ByteArray(headerLen + len)
        frame[0] = 0x82.toByte() // FIN + Opcode Binary (2)

        var idx = 1
        when {
            len < 126 -> {
                frame[idx++] = (0x80 or len).toByte()
            }
            len <= 65535 -> {
                frame[idx++] = (0x80 or 126).toByte()
                frame[idx++] = (len shr 8).toByte()
                frame[idx++] = (len and 0xFF).toByte()
            }
            else -> {
                frame[idx++] = (0x80 or 127).toByte()
                for (i in 7 downTo 0) {
                    frame[idx++] = (len.toLong() shr (i * 8)).toByte()
                }
            }
        }

        System.arraycopy(maskKey, 0, frame, idx, 4)
        idx += 4

        for (i in 0 until len) {
            frame[idx + i] = (data[i].toInt() xor maskKey[i % 4].toInt()).toByte()
        }
        return frame
    }

    /**
     * قراءة إطار WebSocket كامل من الخادم
     */
    private fun readWsBinaryFrame(dataIn: DataInputStream): ByteArray? {
        val b0 = dataIn.read()
        if (b0 == -1) return null
        val opcode = b0 and 0x0F
        if (opcode == 0x08) return null // Close Frame

        val b1 = dataIn.read()
        if (b1 == -1) return null
        val isMasked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()

        if (payloadLen == 126L) {
            payloadLen = dataIn.readUnsignedShort().toLong()
        } else if (payloadLen == 127L) {
            payloadLen = dataIn.readLong()
        }

        if (payloadLen > 1024 * 1024 || payloadLen < 0) return null

        val maskKey = if (isMasked) {
            val m = ByteArray(4)
            dataIn.readFully(m)
            m
        } else null

        val payload = ByteArray(payloadLen.toInt())
        dataIn.readFully(payload)

        if (maskKey != null) {
            for (i in payload.indices) {
                payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            }
        }

        return payload
    }

    private fun buildWebSocketUpgrade(profile: VpnProfile): ByteArray {
        val path = if (profile.path.isNotBlank()) profile.path else "/morocco6"
        val host = if (profile.sniHost.isNotBlank()) profile.sniHost else "m.facebook.com"
        val req = "GET $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "Sec-WebSocket-Version: 13\r\n\r\n"
        return req.toByteArray(Charsets.UTF_8)
    }

    private fun readHttpResponse(input: InputStream): String {
        val lineBuffer = StringBuilder()
        var firstLine = ""
        val buffer = ByteArray(1)
        var matchCount = 0
        while (input.read(buffer) != -1) {
            val b = buffer[0].toInt()
            if (firstLine.isEmpty()) {
                if (b == '\n'.code || b == '\r'.code) {
                    if (lineBuffer.isNotEmpty()) {
                        firstLine = lineBuffer.toString()
                    }
                } else {
                    lineBuffer.append(b.toChar())
                }
            }
            if (matchCount == 0 && b == '\r'.code) matchCount++
            else if (matchCount == 1 && b == '\n'.code) matchCount++
            else if (matchCount == 2 && b == '\r'.code) matchCount++
            else if (matchCount == 3 && b == '\n'.code) break
            else matchCount = if (b == '\r'.code) 1 else 0
        }
        return firstLine
    }

    private fun buildVlessHeader(profile: VpnProfile, targetDomain: String, dstIp: String, dstPort: Int): ByteArray {
        val uuidStr = if (profile.uuid.isNotBlank()) profile.uuid else "5ca53c7d-a947-4191-b98d-16ff5cdbd315"
        val uuid = try {
            UUID.fromString(uuidStr)
        } catch (_: Exception) {
            UUID.randomUUID()
        }
        val uuidBytes = ByteBuffer.allocate(16).apply {
            putLong(uuid.mostSignificantBits)
            putLong(uuid.leastSignificantBits)
        }.array()

        if (targetDomain.isNotBlank()) {
            // نمط النطاق Domain Name (نوع العنوان 2)
            val domainBytes = targetDomain.toByteArray(Charsets.US_ASCII)
            val header = ByteArray(1 + 16 + 1 + 1 + 2 + 1 + 1 + domainBytes.size)
            header[0] = 0 // Version 0
            System.arraycopy(uuidBytes, 0, header, 1, 16)
            header[17] = 0 // Addons length
            header[18] = 1 // Command TCP
            header[19] = (dstPort shr 8).toByte()
            header[20] = (dstPort and 0xFF).toByte()
            header[21] = 2 // Address Type 2 = Domain
            header[22] = domainBytes.size.toByte()
            System.arraycopy(domainBytes, 0, header, 23, domainBytes.size)
            return header
        } else {
            // نمط عنوان IPv4 (نوع العنوان 1)
            val ipBytes = InetAddress.getByName(dstIp).address
            val header = ByteArray(1 + 16 + 1 + 1 + 2 + 1 + 4)
            header[0] = 0 // Version 0
            System.arraycopy(uuidBytes, 0, header, 1, 16)
            header[17] = 0 // Addons length
            header[18] = 1 // Command TCP
            header[19] = (dstPort shr 8).toByte()
            header[20] = (dstPort and 0xFF).toByte()
            header[21] = 1 // Address Type 1 = IPv4
            System.arraycopy(ipBytes, 0, header, 22, 4)
            return header
        }
    }

    private fun handleIcmpPing(data: ByteArray, ihl: Int, length: Int, output: FileOutputStream) {
        if (length < ihl + 8) return
        val type = data[ihl].toInt() and 0xFF
        if (type == 8) { // Echo Request -> Echo Reply
            val reply = data.copyOf(length)
            reply[ihl] = 0
            for (i in 0..3) {
                val tmp = reply[12 + i]
                reply[12 + i] = reply[16 + i]
                reply[16 + i] = tmp
            }
            reply[ihl + 2] = 0
            reply[ihl + 3] = 0
            val icmpChecksum = calculateChecksum(reply, ihl, length - ihl)
            reply[ihl + 2] = (icmpChecksum shr 8).toByte()
            reply[ihl + 3] = (icmpChecksum and 0xFF).toByte()

            reply[10] = 0
            reply[11] = 0
            val ipChecksum = calculateChecksum(reply, 0, ihl)
            reply[10] = (ipChecksum shr 8).toByte()
            reply[11] = (ipChecksum and 0xFF).toByte()

            synchronized(output) {
                try {
                    output.write(reply)
                } catch (_: Exception) {}
            }
        }
    }

    private fun sendIcmpPortUnreachable(originalPacket: ByteArray, ihl: Int, totalLength: Int, output: FileOutputStream) {
        val icmpPayloadLen = (ihl + 8).coerceAtMost(totalLength)
        val totalIcmpPacketLen = 20 + 8 + icmpPayloadLen
        val packet = ByteArray(totalIcmpPacketLen)

        // ترويسة IP
        packet[0] = 0x45
        packet[1] = 0x00
        packet[2] = (totalIcmpPacketLen shr 8).toByte()
        packet[3] = (totalIcmpPacketLen and 0xFF).toByte()
        packet[8] = 64.toByte() // TTL
        packet[9] = 1.toByte()  // Protocol ICMP

        // تبديل العناوين
        System.arraycopy(originalPacket, 16, packet, 12, 4) // Src = Dst of original
        System.arraycopy(originalPacket, 12, packet, 16, 4) // Dst = Src of original

        val ipChecksum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // ترويسة ICMP Destination Unreachable (Type 3, Code 3: Port Unreachable)
        packet[20] = 3.toByte() // Type
        packet[21] = 3.toByte() // Code: Port Unreachable

        // نسخ ترويسة IP الأصلية + أول 8 بايت من UDP
        System.arraycopy(originalPacket, 0, packet, 28, icmpPayloadLen)

        val icmpChecksum = calculateChecksum(packet, 20, 8 + icmpPayloadLen)
        packet[22] = (icmpChecksum shr 8).toByte()
        packet[23] = (icmpChecksum and 0xFF).toByte()

        synchronized(output) {
            try {
                output.write(packet)
            } catch (_: Exception) {}
        }
    }

    // ==========================================
    // دوال بناء حزم IPv4 / UDP / TCP
    // ==========================================

    private fun buildUdpPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength = 20 + 8 + payload.size
        val packet = ByteArray(totalLength)

        packet[0] = 0x45
        packet[1] = 0x00
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        packet[4] = 0x00
        packet[5] = 0x01
        packet[6] = 0x00
        packet[7] = 0x00
        packet[8] = 64.toByte()
        packet[9] = 17.toByte() // UDP

        val srcBytes = InetAddress.getByName(srcIp).address
        val dstBytes = InetAddress.getByName(dstIp).address
        System.arraycopy(srcBytes, 0, packet, 12, 4)
        System.arraycopy(dstBytes, 0, packet, 16, 4)

        val ipChecksum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val udpLength = 8 + payload.size
        packet[20] = (srcPort shr 8).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = (dstPort shr 8).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[24] = (udpLength shr 8).toByte()
        packet[25] = (udpLength and 0xFF).toByte()
        packet[26] = 0
        packet[27] = 0

        System.arraycopy(payload, 0, packet, 28, payload.size)
        return packet
    }

    private fun buildTcpPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength = 20 + 20 + payload.size
        val packet = ByteArray(totalLength)

        packet[0] = 0x45
        packet[1] = 0x00
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        packet[4] = 0x00
        packet[5] = 0x02
        packet[6] = 0x40 // Don't Fragment
        packet[7] = 0x00
        packet[8] = 64.toByte()
        packet[9] = 6.toByte() // TCP

        val srcBytes = InetAddress.getByName(srcIp).address
        val dstBytes = InetAddress.getByName(dstIp).address
        System.arraycopy(srcBytes, 0, packet, 12, 4)
        System.arraycopy(dstBytes, 0, packet, 16, 4)

        val ipChecksum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val tcpOffset = 20
        packet[tcpOffset] = (srcPort shr 8).toByte()
        packet[tcpOffset + 1] = (srcPort and 0xFF).toByte()
        packet[tcpOffset + 2] = (dstPort shr 8).toByte()
        packet[tcpOffset + 3] = (dstPort and 0xFF).toByte()

        packet[tcpOffset + 4] = (seq shr 24).toByte()
        packet[tcpOffset + 5] = (seq shr 16).toByte()
        packet[tcpOffset + 6] = (seq shr 8).toByte()
        packet[tcpOffset + 7] = (seq and 0xFF).toByte()

        packet[tcpOffset + 8] = (ack shr 24).toByte()
        packet[tcpOffset + 9] = (ack shr 16).toByte()
        packet[tcpOffset + 10] = (ack shr 8).toByte()
        packet[tcpOffset + 11] = (ack and 0xFF).toByte()

        packet[tcpOffset + 12] = (5 shl 4).toByte()
        packet[tcpOffset + 13] = flags.toByte()
        packet[tcpOffset + 14] = (65535 shr 8).toByte()
        packet[tcpOffset + 15] = (65535 and 0xFF).toByte()

        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, packet, 40, payload.size)
        }

        val tcpChecksum = calculateTcpChecksum(packet, srcBytes, dstBytes, 20 + payload.size)
        packet[tcpOffset + 16] = (tcpChecksum shr 8).toByte()
        packet[tcpOffset + 17] = (tcpChecksum and 0xFF).toByte()

        return packet
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv()) and 0xFFFF
    }

    private fun calculateTcpChecksum(packet: ByteArray, srcIp: ByteArray, dstIp: ByteArray, tcpLength: Int): Int {
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += 6
        sum += tcpLength

        var i = 20
        val end = 20 + tcpLength
        while (i < end - 1) {
            if (i != 36) {
                sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            }
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv()) and 0xFFFF
    }

    private fun getIpAddress(data: ByteArray, offset: Int): String {
        return "${data[offset].toInt() and 0xFF}.${data[offset + 1].toInt() and 0xFF}.${data[offset + 2].toInt() and 0xFF}.${data[offset + 3].toInt() and 0xFF}"
    }

    private fun getShort(data: ByteArray, offset: Int): Short {
        return (((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)).toShort()
    }

    private fun getInt(data: ByteArray, offset: Int): Long {
        return (((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF))
    }

    private fun closeAllConnections() {
        tcpConnections.values.forEach { it.close() }
        tcpConnections.clear()
    }

    fun stop() {
        isRunning = false
        closeAllConnections()
    }

    private class TcpConnectionState(
        val srcIp: String,
        val srcPort: Int,
        val dstIp: String,
        val dstPort: Int,
        val targetDomain: String,
        var clientSeq: Long,
        var serverSeq: Long
    ) {
        var outboundSocket: Socket? = null
        var onSendData: ((ByteArray) -> Unit)? = null
        private val pendingQueue = ArrayList<ByteArray>()

        fun sendPayload(data: ByteArray) {
            val sender = onSendData
            if (sender != null) {
                sender(data)
            } else {
                synchronized(pendingQueue) {
                    if (pendingQueue.size < 50) {
                        pendingQueue.add(data)
                    }
                }
            }
        }

        fun flushPendingData() {
            val sender = onSendData ?: return
            synchronized(pendingQueue) {
                for (item in pendingQueue) {
                    sender(item)
                }
                pendingQueue.clear()
            }
        }

        fun close() {
            try { outboundSocket?.close() } catch (_: Exception) {}
            outboundSocket = null
        }
    }
}
