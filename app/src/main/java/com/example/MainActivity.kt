package com.example

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.example.ui.theme.CardBorder
import com.example.ui.theme.CyberBlue
import com.example.ui.theme.CyberBlueLight
import com.example.ui.theme.CyberGreen
import com.example.ui.theme.CyberRed
import com.example.ui.theme.CyberYellow
import com.example.ui.theme.DarkBackground
import com.example.ui.theme.DarkSurface
import com.example.ui.theme.DarkSurfaceElevated
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.vpn.DiagnosticResult
import com.example.vpn.LocalVpnService
import com.example.vpn.MOROCCAN_STAR_6_BUG_HOSTS
import com.example.vpn.ProxyProtocol
import com.example.vpn.TrafficStats
import com.example.vpn.VpnProfile
import com.example.vpn.VpnStateManager
import com.example.vpn.VpnStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            MyApplicationTheme {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    Scaffold(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(DarkBackground)
                    ) { innerPadding ->
                        VpnMainScreen(
                            modifier = Modifier.padding(innerPadding)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun VpnMainScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val vpnStatus by VpnStateManager.status.collectAsState()
    val trafficStats by VpnStateManager.trafficStats.collectAsState()
    val logMessages by VpnStateManager.logMessages.collectAsState()

    // قائمة الخوادم الافتراضية - السيرفر يدعم VLESS WebSocket على المنفذين 80 و 443
    // المنفذ 80: HTTP WebSocket (بدون TLS) - للاستخدام مع ثغرة SNI على *6 إنوي
    // المنفذ 443: HTTPS WebSocket (مع TLS + شهادة ذاتية) - مشفر بالكامل
    val defaultProfiles = remember {
        listOf(
            VpnProfile(
                id = "inwi_star6_tls_443",
                name = "🔒 إنوي *6 المشفر (منفذ 443 TLS - الأفضل لـ Google)",
                host = "187.77.168.45",
                port = 443,
                protocol = ProxyProtocol.VLESS,
                dns = "8.8.8.8",
                sniHost = "m.facebook.com",
                uuid = "5ca53c7d-a947-4191-b98d-16ff5cdbd315",
                path = "/morocco6",
                transport = "ws"
            ),
            VpnProfile(
                id = "inwi_star6_ws_direct_80",
                name = "⚡ إنوي *6 السريع (منفذ 80 HTTP WebSocket)",
                host = "187.77.168.45",
                port = 80,
                protocol = ProxyProtocol.VLESS,
                dns = "8.8.8.8",
                sniHost = "m.facebook.com",
                uuid = "5ca53c7d-a947-4191-b98d-16ff5cdbd315",
                path = "/morocco6",
                transport = "ws"
            ),
            VpnProfile(
                id = "inwi_star6_wa_443",
                name = "إنوي نجمة 6 - ثغرة WhatsApp Web (منفذ 443)",
                host = "187.77.168.45",
                port = 443,
                protocol = ProxyProtocol.VLESS,
                dns = "1.1.1.1",
                sniHost = "web.whatsapp.com",
                uuid = "5ca53c7d-a947-4191-b98d-16ff5cdbd315",
                path = "/morocco6",
                transport = "ws"
            ),
            VpnProfile(
                id = "inwi_star6_tt_443",
                name = "إنوي نجمة 6 - ثغرة TikTok CDN (منفذ 443)",
                host = "187.77.168.45",
                port = 443,
                protocol = ProxyProtocol.VLESS,
                dns = "8.8.8.8",
                sniHost = "v16-webapp-prime.tiktok.com",
                uuid = "5ca53c7d-a947-4191-b98d-16ff5cdbd315",
                path = "/morocco6",
                transport = "ws"
            ),
            VpnProfile(
                id = "inwi_star6_fb_80",
                name = "إنوي نجمة 6 - ثغرة Facebook (منفذ 80 بدون TLS)",
                host = "187.77.168.45",
                port = 80,
                protocol = ProxyProtocol.VLESS,
                dns = "8.8.8.8",
                sniHost = "m.facebook.com",
                uuid = "5ca53c7d-a947-4191-b98d-16ff5cdbd315",
                path = "/morocco6",
                transport = "ws"
            )
        )
    }

    var selectedProfile by remember { mutableStateOf(defaultProfiles[0]) }
    var showCustomDialog by remember { mutableStateOf(false) }
    var showPermissionExplanation by remember { mutableStateOf(false) }
    var selectedTabIndex by remember { mutableIntStateOf(0) }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { }
    )

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService(context, selectedProfile)
        } else {
            VpnStateManager.addLog("تم رفض صلاحية الـ VPN من المستخدم.")
        }
    }

    val handleToggleVpn = {
        if (vpnStatus == VpnStatus.CONNECTED || vpnStatus == VpnStatus.CONNECTING) {
            stopVpnService(context)
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }

            val intent = VpnService.prepare(context)
            if (intent != null) {
                showPermissionExplanation = true
            } else {
                startVpnService(context, selectedProfile)
            }
        }
    }

    if (showPermissionExplanation) {
        AlertDialog(
            onDismissRequest = { showPermissionExplanation = false },
            icon = { Icon(Icons.Default.Security, contentDescription = null, tint = CyberBlue) },
            title = { Text("طلب إنشاء نفق VPN", fontWeight = FontWeight.Bold, color = TextPrimary) },
            text = {
                Text(
                    "يحتاج التطبيق إلى إنشاء اتصال نفق VPN محلي آمن على جهازك لتوجيه وتشفير حركة البيانات وحمايتها، وتخطي قيود حظر المواقع مثل google.com عبر ثغرات SNI في عرض *6.\n\nسيظهر لك الآن طلب من نظام أندرويد لتأكيد هذا الإجراء.",
                    color = TextSecondary,
                    lineHeight = 22.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showPermissionExplanation = false
                        val intent = VpnService.prepare(context)
                        if (intent != null) {
                            vpnPermissionLauncher.launch(intent)
                        } else {
                            startVpnService(context, selectedProfile)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberBlue)
                ) {
                    Text("متابعة والموافقة", color = Color.White)
                }
            },
            dismissButton = {
                TextButton(onClick = { showPermissionExplanation = false }) {
                    Text("إلغاء", color = TextMuted)
                }
            },
            containerColor = DarkSurfaceElevated
        )
    }

    if (showCustomDialog) {
        CustomProxyDialog(
            currentProfile = selectedProfile,
            onDismiss = { showCustomDialog = false },
            onSave = { newProfile ->
                selectedProfile = newProfile
                showCustomDialog = false
                VpnStateManager.addLog("تم حفظ الإعداد المخصص: ${newProfile.name}")
            }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(DarkBackground)
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        TopHeaderBar()

        Spacer(modifier = Modifier.height(14.dp))

        // شريط التبويبات الأربعة
        TabRow(
            selectedTabIndex = selectedTabIndex,
            containerColor = DarkSurface,
            contentColor = CyberBlueLight,
            indicator = { tabPositions ->
                TabRowDefaults.SecondaryIndicator(
                    modifier = Modifier.tabIndicatorOffset(tabPositions[selectedTabIndex]),
                    color = CyberBlue
                )
            },
            modifier = Modifier
                .clip(RoundedCornerShape(12.dp))
                .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
        ) {
            Tab(
                selected = selectedTabIndex == 0,
                onClick = { selectedTabIndex = 0 },
                text = { Text("الرئيسية", fontWeight = FontWeight.SemiBold, fontSize = 13.sp) },
                icon = { Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
            Tab(
                selected = selectedTabIndex == 1,
                onClick = { selectedTabIndex = 1 },
                text = { Text("عروض *6", fontWeight = FontWeight.SemiBold, fontSize = 13.sp) },
                icon = { Icon(Icons.Default.Star, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
            Tab(
                selected = selectedTabIndex == 2,
                onClick = { selectedTabIndex = 2 },
                text = { Text("فاحص Google", fontWeight = FontWeight.SemiBold, fontSize = 13.sp) },
                icon = { Icon(Icons.Default.NetworkCheck, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
            Tab(
                selected = selectedTabIndex == 3,
                onClick = { selectedTabIndex = 3 },
                text = { Text("السجل", fontWeight = FontWeight.SemiBold, fontSize = 13.sp) },
                icon = { Icon(Icons.Default.Info, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        when (selectedTabIndex) {
            0 -> {
                DashboardTab(
                    vpnStatus = vpnStatus,
                    trafficStats = trafficStats,
                    selectedProfile = selectedProfile,
                    onToggleVpn = handleToggleVpn,
                    onOpenSettings = { selectedTabIndex = 1 },
                    onSelectInwiProfile = {
                        selectedProfile = defaultProfiles[0]
                        VpnStateManager.addLog("تم تحديد إعداد إنوي *6 (Facebook SNI) كخادم نشط")
                    }
                )
            }
            1 -> {
                ServersTab(
                    profiles = defaultProfiles,
                    selectedProfile = selectedProfile,
                    onSelectProfile = { selectedProfile = it },
                    onOpenCustomDialog = { showCustomDialog = true }
                )
            }
            2 -> {
                DiagnosticTab(selectedProfile = selectedProfile)
            }
            3 -> {
                LogsTab(logs = logMessages)
            }
        }
    }
}

@Composable
fun TopHeaderBar() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(DarkSurface)
            .border(1.dp, CardBorder, RoundedCornerShape(16.dp))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(
                        Brush.linearGradient(listOf(CyberBlue, Color(0xFF0284C7)))
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Security,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(24.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(
                    text = "Remix VPN Proxy Client",
                    color = TextPrimary,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "دعم عروض نجمة 6 إنوي وتخطي حظر Google",
                    color = CyberBlueLight,
                    fontSize = 11.sp
                )
            }
        }

        Surface(
            color = DarkSurfaceElevated,
            shape = RoundedCornerShape(20.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = null,
                    tint = CyberGreen,
                    modifier = Modifier.size(13.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    "Inwi *6 Ready",
                    fontSize = 10.sp,
                    color = CyberGreen,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
fun DashboardTab(
    vpnStatus: VpnStatus,
    trafficStats: TrafficStats,
    selectedProfile: VpnProfile,
    onToggleVpn: () -> Unit,
    onOpenSettings: () -> Unit,
    onSelectInwiProfile: () -> Unit
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // بطاقة توضيح وإرشاد خاصة بعرض *6 إنوي وتفسير مشكلة google.com
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = DarkSurfaceElevated),
            shape = RoundedCornerShape(16.dp),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                if (selectedProfile.isStar6Profile) CyberGreen.copy(alpha = 0.5f) else CyberYellow.copy(alpha = 0.5f)
            )
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (selectedProfile.isStar6Profile) Icons.Default.CheckCircle else Icons.Default.Warning,
                            contentDescription = null,
                            tint = if (selectedProfile.isStar6Profile) CyberGreen else CyberYellow,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "ملاحظة عرض *6 إنوي (Inwi)",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        color = (if (selectedProfile.isStar6Profile) CyberGreen else CyberYellow).copy(alpha = 0.15f),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            text = if (selectedProfile.isStar6Profile) "وضع *6 مفعّل" else "عرض *6 يتطلب ضبط",
                            color = if (selectedProfile.isStar6Profile) CyberGreen else CyberYellow,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "موقع google.com لا يعمل لديك بشكل مباشر لأن عرض *6 إنوي محصور بمواقع التواصل الاجتماعي (فيسبوك، واتساب) وتقوم إنوي بحظر جوجل والإنترنت العام. لتشغيل Google، استخدم نفق VPN مع ثغرة SNI (مثل m.facebook.com) ليتم تحويل رصيد *6 إلى إنترنت كامل.",
                    color = TextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )

                if (!selectedProfile.isStar6Profile) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = onSelectInwiProfile,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberBlue),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            "⚡ تطبيق إعداد إنوي *6 (Facebook SNI) الآن",
                            fontSize = 12.sp,
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                    }
                } else {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "ثغرة الـ SNI الحالية: ${selectedProfile.sniHost} (جاهز لتخطي حظر Google عبر المنفذ 443)",
                        color = CyberBlueLight,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }

        // بطاقة الخادم المحدد حالياً
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onOpenSettings() }
                .testTag("selected_server_card"),
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            shape = RoundedCornerShape(16.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CircleShape)
                            .background(DarkSurfaceElevated),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.Router,
                            contentDescription = null,
                            tint = CyberBlueLight,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = selectedProfile.name,
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
                        )
                        val subText = if (selectedProfile.sniHost.isNotBlank()) {
                            "SNI: ${selectedProfile.sniHost} • ${selectedProfile.host}:${selectedProfile.port}"
                        } else {
                            "${selectedProfile.protocol.displayName} • ${selectedProfile.host}:${selectedProfile.port}"
                        }
                        Text(
                            text = subText,
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                }
                Text(
                    text = "تغيير",
                    color = CyberBlue,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }

        // زر تشغيل/إيقاف النفق الكبير
        VpnPowerButton(
            status = vpnStatus,
            onClick = onToggleVpn
        )

        // مؤشر حالة الاتصال ومدة العمل
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            val statusColor by animateColorAsState(
                targetValue = when (vpnStatus) {
                    VpnStatus.CONNECTED -> CyberGreen
                    VpnStatus.CONNECTING -> CyberYellow
                    VpnStatus.DISCONNECTING -> CyberYellow
                    VpnStatus.DISCONNECTED -> TextMuted
                },
                label = "status_color"
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = when (vpnStatus) {
                        VpnStatus.CONNECTED -> "النفق متصل وآمن (Google يعمل الآن)"
                        VpnStatus.CONNECTING -> "جارٍ إنشاء النفق وتخطي الحظر..."
                        VpnStatus.DISCONNECTING -> "جارٍ قطع الاتصال..."
                        VpnStatus.DISCONNECTED -> "غير متصل (النفق متوقف)"
                    },
                    color = statusColor,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            if (vpnStatus == VpnStatus.CONNECTED) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "مدة الاتصال: ${trafficStats.formatDuration()}",
                    color = TextSecondary,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        }

        // إحصائيات استهلاك البيانات
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = DarkSurface),
            shape = RoundedCornerShape(16.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Speed,
                        contentDescription = null,
                        tint = CyberBlue,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "إحصائيات تدفق واستهلاك البيانات",
                        color = TextPrimary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatBox(
                        title = "البيانات الصادرة (Upload)",
                        value = trafficStats.formatBytes(trafficStats.bytesOut),
                        subValue = "${trafficStats.uploadSpeedKbps} Kbps",
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    StatBox(
                        title = "البيانات الواردة (Download)",
                        value = trafficStats.formatBytes(trafficStats.bytesIn),
                        subValue = "${trafficStats.downloadSpeedKbps} Kbps",
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

@Composable
fun VpnPowerButton(
    status: VpnStatus,
    onClick: () -> Unit
) {
    val isConnected = status == VpnStatus.CONNECTED
    val isBusy = status == VpnStatus.CONNECTING || status == VpnStatus.DISCONNECTING

    val buttonColor by animateColorAsState(
        targetValue = when (status) {
            VpnStatus.CONNECTED -> CyberGreen
            VpnStatus.CONNECTING -> CyberYellow
            VpnStatus.DISCONNECTING -> CyberYellow
            VpnStatus.DISCONNECTED -> CyberBlue
        },
        label = "btn_color"
    )

    val scale by animateFloatAsState(
        targetValue = if (isConnected) 1.05f else 1f,
        animationSpec = tween(300),
        label = "btn_scale"
    )

    Box(
        modifier = Modifier
            .size(160.dp)
            .scale(scale)
            .clip(CircleShape)
            .background(DarkSurface)
            .border(
                width = 3.dp,
                brush = Brush.radialGradient(
                    colors = listOf(buttonColor, buttonColor.copy(alpha = 0.2f))
                ),
                shape = CircleShape
            )
            .clickable(enabled = !isBusy) { onClick() }
            .testTag("vpn_power_button"),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .size(125.dp)
                .clip(CircleShape)
                .background(buttonColor.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            if (isBusy) {
                CircularProgressIndicator(
                    color = buttonColor,
                    modifier = Modifier.size(50.dp),
                    strokeWidth = 3.dp
                )
            } else {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        Icons.Default.PowerSettingsNew,
                        contentDescription = "تشغيل أو إيقاف الـ VPN",
                        tint = buttonColor,
                        modifier = Modifier.size(46.dp)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (isConnected) "إيقاف" else "اتصال",
                        color = TextPrimary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun StatBox(
    title: String,
    value: String,
    subValue: String,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(DarkSurfaceElevated)
            .border(1.dp, CardBorder, RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Column {
            Text(text = title, color = TextSecondary, fontSize = 11.sp)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                color = TextPrimary,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subValue,
                color = CyberBlueLight,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

@Composable
fun ServersTab(
    profiles: List<VpnProfile>,
    selectedProfile: VpnProfile,
    onSelectProfile: (VpnProfile) -> Unit,
    onOpenCustomDialog: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        "خوادم وإعدادات عروض إنوي *6",
                        color = TextPrimary,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        "اختر إعداداً مجهزاً بثغرة SNI لفتح google.com",
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }
                Button(
                    onClick = onOpenCustomDialog,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberBlue),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("add_custom_proxy_button")
                ) {
                    Text("+ إضافة يدوي", fontSize = 12.sp, color = Color.White)
                }
            }
        }

        // قسم عروض نجمة 6
        item {
            Text(
                "🌟 خوادم مخصصة لعرض نجمة 6 (Inwi *6 Presets)",
                color = CyberYellow,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 6.dp)
            )
        }

        val star6Profiles = profiles.filter { it.isStar6Profile }
        items(star6Profiles) { profile ->
            ProfileCardItem(
                profile = profile,
                isSelected = profile.id == selectedProfile.id,
                onSelect = { onSelectProfile(profile) }
            )
        }

        // قسم الخوادم العامة
        item {
            Text(
                "🌐 خوادم وبروكسيات عامة (Standard)",
                color = TextSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        val standardProfiles = profiles.filter { !it.isStar6Profile }
        items(standardProfiles) { profile ->
            ProfileCardItem(
                profile = profile,
                isSelected = profile.id == selectedProfile.id,
                onSelect = { onSelectProfile(profile) }
            )
        }

        // شرح فني مبسط لكيفية تشغيل google.com مع نجمة 6
        item {
            Spacer(modifier = Modifier.height(6.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            "كيف يعمل تجاوز حظر google.com في *6؟",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "1. عرض نجمة 6 في إنوي يعطي وصولاً مجانياً لمواقع فيسبوك وواتساب وتيك توك فقط.\n" +
                        "2. يتم استخدام تقنية SNI Spoofing (تزييف رأس الاتصال) مثل m.facebook.com بحيث تظن شركة إنوي أنك تتصفح فيسبوك.\n" +
                        "3. يقوم خادم النفق في الطرف الآخر بفك الحظر وجلب صفحات google.com وتمريرها إليك كاملة.",
                        color = TextMuted,
                        fontSize = 11.sp,
                        lineHeight = 17.sp
                    )
                }
            }
        }
    }
}

@Composable
fun ProfileCardItem(
    profile: VpnProfile,
    isSelected: Boolean,
    onSelect: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect() }
            .testTag("server_item_${profile.id}"),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) DarkSurfaceElevated else DarkSurface
        ),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            if (isSelected) CyberBlue else CardBorder
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .clip(CircleShape)
                        .background(if (isSelected) CyberBlue.copy(alpha = 0.2f) else DarkSurfaceElevated),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = if (profile.isStar6Profile) Icons.Default.Star else Icons.Default.Dns,
                        contentDescription = null,
                        tint = if (isSelected) CyberBlue else if (profile.isStar6Profile) CyberYellow else TextSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = profile.name,
                            color = TextPrimary,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp
                        )
                    }
                    val detailsText = if (profile.sniHost.isNotBlank()) {
                        "ثغرة SNI: ${profile.sniHost} • المنفذ: ${profile.port}"
                    } else {
                        "${profile.protocol.displayName} • ${profile.host}:${profile.port}"
                    }
                    Text(
                        text = detailsText,
                        color = if (profile.sniHost.isNotBlank()) CyberBlueLight else TextSecondary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            if (isSelected) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = "محدد",
                    tint = CyberGreen,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

/**
 * أداة تشخيص شبكة إنوي واختبار google.com وعرض *6
 */
@Composable
fun DiagnosticTab(selectedProfile: VpnProfile) {
    val coroutineScope = rememberCoroutineScope()
    var isRunningTests by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf<List<DiagnosticResult>>(emptyList()) }
    var overallAdvice by remember { mutableStateOf<String?>(null) }

    fun runTests() {
        isRunningTests = true
        results = emptyList()
        overallAdvice = null

        coroutineScope.launch {
            val list = mutableListOf<DiagnosticResult>()

            // 1. اختبار الاتصال بـ google.com
            val googleResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress("google.com", 80), 3000)
                    val latency = System.currentTimeMillis() - start
                    socket.close()
                    DiagnosticResult(
                        title = "فحص الوصول إلى موقع google.com",
                        target = "google.com:80",
                        isSuccess = true,
                        latencyMs = latency,
                        message = "تم الاتصال بنجاح! موقع google.com متاح ويعمل."
                    )
                } catch (e: Exception) {
                    DiagnosticResult(
                        title = "فحص الوصول إلى موقع google.com",
                        target = "google.com:80",
                        isSuccess = false,
                        latencyMs = 0L,
                        message = "محجوب أو غير متاح: لا يوجد رصيد إنترنت عام (عرض *6 محصور بمواقع التواصل فقط)."
                    )
                }
            }
            list.add(googleResult)

            // 2. اختبار ثغرة Facebook (*6 SNI Host)
            val fbBugResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress("m.facebook.com", 443), 3000)
                    val latency = System.currentTimeMillis() - start
                    socket.close()
                    DiagnosticResult(
                        title = "فحص ثغرة إنوي *6 (Facebook SNI)",
                        target = "m.facebook.com:443",
                        isSuccess = true,
                        latencyMs = latency,
                        message = "الثغرة تعمل بنجاح! شبكة إنوي تسمح بمرور هذا العنوان في عرض *6."
                    )
                } catch (e: Exception) {
                    DiagnosticResult(
                        title = "فحص ثغرة إنوي *6 (Facebook SNI)",
                        target = "m.facebook.com:443",
                        isSuccess = false,
                        latencyMs = 0L,
                        message = "تعذر الاتصال بـ m.facebook.com، تأكد من تشغيل بيانات الهاتف لشريحة إنوي."
                    )
                }
            }
            list.add(fbBugResult)

            // 3. اختبار ثغرة WhatsApp (*6 SNI Host)
            val waBugResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress("web.whatsapp.com", 443), 3000)
                    val latency = System.currentTimeMillis() - start
                    socket.close()
                    DiagnosticResult(
                        title = "فحص ثغرة إنوي *6 (WhatsApp SNI)",
                        target = "web.whatsapp.com:443",
                        isSuccess = true,
                        latencyMs = latency,
                        message = "متاحة بنجاح كبديل لنفق الـ VPN."
                    )
                } catch (e: Exception) {
                    DiagnosticResult(
                        title = "فحص ثغرة إنوي *6 (WhatsApp SNI)",
                        target = "web.whatsapp.com:443",
                        isSuccess = false,
                        latencyMs = 0L,
                        message = "غير مستجيبة حالياً."
                    )
                }
            }
            list.add(waBugResult)

            // 4. اختبار خادم الـ VPN المختار (TCP)
            val serverResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                try {
                    val socket = Socket()
                    socket.connect(InetSocketAddress(selectedProfile.host, selectedProfile.port), 4000)
                    val latency = System.currentTimeMillis() - start
                    socket.close()
                    DiagnosticResult(
                        title = "1. منفذ الخادم (TCP Port ${selectedProfile.port})",
                        target = "${selectedProfile.host}:${selectedProfile.port}",
                        isSuccess = true,
                        latencyMs = latency,
                        message = "منفذ السيرفر مفتوح ويستجيب بنجاح."
                    )
                } catch (e: Exception) {
                    DiagnosticResult(
                        title = "1. منفذ الخادم (TCP Port ${selectedProfile.port})",
                        target = "${selectedProfile.host}:${selectedProfile.port}",
                        isSuccess = false,
                        latencyMs = 0L,
                        message = "فشل الاتصال: ${e.message ?: "السيرفر لا يستجيب أو جدار الحماية UFW مغلق"}."
                    )
                }
            }
            list.add(serverResult)

            // 5. فحص مصافحة WebSocket (HTTP أو HTTPS حسب المنفذ)
            val isTlsProfile = selectedProfile.port == 443 && selectedProfile.protocol != ProxyProtocol.SOCKS5
            val tlsResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                if (isTlsProfile) {
                    // فحص TLS للمنفذ 443
                    try {
                        val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate>? = null
                            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                        })
                        val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                            init(null, trustAll, java.security.SecureRandom())
                        }
                        val rawSock = Socket()
                        rawSock.connect(InetSocketAddress(selectedProfile.host, selectedProfile.port), 4000)
                        val sslSock = sslCtx.socketFactory.createSocket(rawSock, selectedProfile.host, selectedProfile.port, true) as javax.net.ssl.SSLSocket
                        if (selectedProfile.sniHost.isNotBlank()) {
                            val params = sslSock.sslParameters
                            params.serverNames = listOf(javax.net.ssl.SNIHostName(selectedProfile.sniHost))
                            sslSock.sslParameters = params
                        }
                        sslSock.startHandshake()
                        val latency = System.currentTimeMillis() - start
                        sslSock.close()
                        DiagnosticResult(
                            title = "2. تشفير TLS و ثغرة SNI (${selectedProfile.sniHost})",
                            target = "${selectedProfile.host} [SNI: ${selectedProfile.sniHost}]",
                            isSuccess = true,
                            latencyMs = latency,
                            message = "تمت مصافحة TLS بنجاح مع ثغرة SNI."
                        )
                    } catch (e: Exception) {
                        DiagnosticResult(
                            title = "2. تشفير TLS و ثغرة SNI (${selectedProfile.sniHost})",
                            target = "${selectedProfile.host} [SNI: ${selectedProfile.sniHost}]",
                            isSuccess = false,
                            latencyMs = 0L,
                            message = "فشلت مصافحة TLS: ${e.message ?: "الخادم لا يدعم TLS على هذا المنفذ"}."
                        )
                    }
                } else {
                    // المنفذ 80: الاتصال HTTP عادي بدون TLS - هذا صحيح!
                    DiagnosticResult(
                        title = "2. وضع الاتصال: HTTP WebSocket (منفذ ${selectedProfile.port} - بدون TLS)",
                        target = "${selectedProfile.host}:${selectedProfile.port}",
                        isSuccess = true,
                        latencyMs = System.currentTimeMillis() - start,
                        message = "✅ المنفذ ${selectedProfile.port} يعمل بـ HTTP WebSocket العادي (بدون تشفير TLS). هذا صحيح لعرض *6 إنوي - الحماية تأتي من داخل بروتوكول VLESS."
                    )
                }
            }
            list.add(tlsResult)

            // 6. فحص مصافحة WebSocket الحقيقية على مسار الخادم
            val wsResult = withContext(Dispatchers.IO) {
                val start = System.currentTimeMillis()
                try {
                    val path = if (selectedProfile.path.isNotBlank()) selectedProfile.path else "/morocco6"
                    val hostHeader = if (selectedProfile.sniHost.isNotBlank()) selectedProfile.sniHost else "m.facebook.com"
                    val wsReq = "GET $path HTTP/1.1\r\n" +
                            "Host: $hostHeader\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                            "Sec-WebSocket-Version: 13\r\n\r\n"

                    val sockForWs = Socket()
                    sockForWs.connect(InetSocketAddress(selectedProfile.host, selectedProfile.port), 5000)

                    // استخدام TLS فقط للمنفذ 443، وإلا HTTP مباشر
                    val streamToUse = if (isTlsProfile) {
                        val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate>? = null
                            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                        })
                        val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                            init(null, trustAll, java.security.SecureRandom())
                        }
                        val sslSock = sslCtx.socketFactory.createSocket(sockForWs, selectedProfile.host, selectedProfile.port, true) as javax.net.ssl.SSLSocket
                        if (selectedProfile.sniHost.isNotBlank()) {
                            val params = sslSock.sslParameters
                            params.serverNames = listOf(javax.net.ssl.SNIHostName(selectedProfile.sniHost))
                            sslSock.sslParameters = params
                        }
                        sslSock.startHandshake()
                        Pair(sslSock.getOutputStream(), sslSock.getInputStream())
                    } else {
                        Pair(sockForWs.getOutputStream(), sockForWs.getInputStream())
                    }

                    streamToUse.first.write(wsReq.toByteArray(Charsets.UTF_8))
                    streamToUse.first.flush()

                    val br = java.io.BufferedReader(java.io.InputStreamReader(streamToUse.second))
                    val responseLine = br.readLine() ?: "لا يوجد رد"
                    val latency = System.currentTimeMillis() - start
                    sockForWs.close()

                    val is101 = responseLine.contains("101")
                    DiagnosticResult(
                        title = "3. مسار WebSocket في السيرفر (Path: $path - منفذ ${selectedProfile.port})",
                        target = "$path via $hostHeader",
                        isSuccess = is101,
                        latencyMs = latency,
                        message = if (is101) "✅ استجاب السيرفر بنجاح: $responseLine (VLESS WS جاهز 100%)\nالتطبيق سيعمل بشكل صحيح عند الضغط على 'اتصال'."
                        else "⚠️ رد السيرفر: $responseLine (تأكد من مطابقة Path: $path مع إعدادات Xray في VPS)"
                    )
                } catch (e: Exception) {
                    DiagnosticResult(
                        title = "3. مسار WebSocket في السيرفر",
                        target = selectedProfile.path,
                        isSuccess = false,
                        latencyMs = 0L,
                        message = "تعذر فحص الـ WebSocket: ${e.message}"
                    )
                }
            }
            list.add(wsResult)

            results = list
            isRunningTests = false

            // إعداد التقرير التوجيهي
            overallAdvice = if (!serverResult.isSuccess) {
                "🔴 المشكلة من الخادم (VPS): تعذر الاتصال بـ ${selectedProfile.host}:${selectedProfile.port}. تأكد من أن السيرفر مشتغل وأن جدار الحماية (UFW) يسمح بالمنفذ ${selectedProfile.port}."
            } else if (isTlsProfile && !tlsResult.isSuccess) {
                "🟠 المشكلة في إعدادات الـ SSL/TLS بالسيرفر: تم فتح المنفذ لكن فشلت مصافحة التشفير TLS."
            } else if (!wsResult.isSuccess) {
                "🟡 المشكلة في مسار WebSocket (Path) في السيرفر: السيرفر متصل لكنه لم يرد بـ 101 Switching Protocols. تأكد من أن مسار الـ WebSocket (${selectedProfile.path}) مطابق لما هو مبرمج في ملف config.json لـ Xray."
            } else if (googleResult.isSuccess) {
                "🟢 كل شيء ممتاز! نفق VLESS يعمل بنجاح وموقع google.com متاح الآن."
            } else {
                "🔵 السيرفر ممتاز وWebSocket جاهز! اضغط على زر 'اتصال' في الصفحة الرئيسية وسيعمل Google فوراً عبر نفق VLESS على المنفذ ${selectedProfile.port}."
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.NetworkCheck, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    "فاحص الاتصال وثغرات *6 إنوي",
                                    color = TextPrimary,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    "تحقق فورياً من سبب تعطل google.com وكفاءة ثغرة الـ SNI",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = { runTests() },
                        enabled = !isRunningTests,
                        colors = ButtonDefaults.buttonColors(containerColor = CyberBlue),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isRunningTests) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("جارٍ فحص الاتصال...", color = Color.White, fontSize = 13.sp)
                        } else {
                            Icon(Icons.Default.Refresh, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("🚀 بدء فحص اتصال google.com وثغرات *6", color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        if (overallAdvice != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = DarkSurfaceElevated),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, CyberBlue)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Info, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("تقرير وتوجيه التشخيص", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = overallAdvice ?: "",
                            color = TextSecondary,
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        }

        if (results.isEmpty() && !isRunningTests) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "اضغط على زر الفحص أعلاه لاختبار إمكانية الوصول إلى google.com وحالة ثغرات إنوي *6.",
                        color = TextMuted,
                        textAlign = TextAlign.Center,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                }
            }
        }

        items(results) { res ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = DarkSurface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    if (res.isSuccess) CyberGreen.copy(alpha = 0.5f) else CyberRed.copy(alpha = 0.5f)
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(modifier = Modifier.weight(1f)) {
                        Icon(
                            imageVector = if (res.isSuccess) Icons.Default.CheckCircle else Icons.Default.Cancel,
                            contentDescription = null,
                            tint = if (res.isSuccess) CyberGreen else CyberRed,
                            modifier = Modifier
                                .size(20.dp)
                                .padding(top = 2.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = res.title,
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                            Text(
                                text = res.target,
                                color = TextMuted,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = res.message,
                                color = if (res.isSuccess) CyberGreen else TextSecondary,
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            )
                        }
                    }

                    if (res.isSuccess && res.latencyMs > 0) {
                        Surface(
                            color = CyberGreen.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = "${res.latencyMs} ms",
                                color = CyberGreen,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun LogsTab(logs: List<String>) {
    Card(
        modifier = Modifier.fillMaxSize(),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, CardBorder)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "سجل أحداث النفق والاتصال",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
                Text(
                    "${logs.size} حدث",
                    color = TextMuted,
                    fontSize = 12.sp
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (logs.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "لا توجد سجلات حالياً.\nقم بتشغيل النفق لمشاهدة الأحداث اللحظية.",
                        color = TextMuted,
                        textAlign = TextAlign.Center,
                        fontSize = 13.sp
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(logs.reversed()) { log ->
                        Text(
                            text = log,
                            color = CyberBlueLight,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CustomProxyDialog(
    currentProfile: VpnProfile,
    onDismiss: () -> Unit,
    onSave: (VpnProfile) -> Unit
) {
    var name by remember { mutableStateOf(currentProfile.name) }
    var host by remember { mutableStateOf(currentProfile.host) }
    var portText by remember { mutableStateOf(currentProfile.port.toString()) }
    var protocol by remember { mutableStateOf(currentProfile.protocol) }
    var sniHost by remember { mutableStateOf(currentProfile.sniHost.ifBlank { "m.facebook.com" }) }
    var uuid by remember { mutableStateOf(currentProfile.uuid.ifBlank { "5ca53c7d-a947-4191-b98d-16ff5cdbd315" }) }
    var path by remember { mutableStateOf(currentProfile.path.ifBlank { "/morocco6" }) }
    var dns by remember { mutableStateOf(currentProfile.dns) }

    val scrollState = rememberScrollState()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("إعداد سيرفر VLESS أو بروكسي مخصص", fontWeight = FontWeight.Bold, color = TextPrimary) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("اسم التكوين") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("custom_proxy_name_input")
                )

                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text("عنوان السيرفر (IP الخاص بالـ VPS)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("custom_proxy_host_input")
                )

                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it },
                    label = { Text("المنفذ (Port) - 443 لـ *6") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("custom_proxy_port_input")
                )

                // معرف الـ UUID لبروتوكول VLESS
                OutlinedTextField(
                    value = uuid,
                    onValueChange = { uuid = it },
                    label = { Text("المعرف (UUID الخاص بـ VLESS / Xray)") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                // مسار الـ WebSocket Path
                OutlinedTextField(
                    value = path,
                    onValueChange = { path = it },
                    label = { Text("مسار الـ WebSocket (Path)") },
                    placeholder = { Text("/morocco6") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                // ثغرة الـ SNI (Bug Host لعرض نجمة 6)
                OutlinedTextField(
                    value = sniHost,
                    onValueChange = { sniHost = it },
                    label = { Text("ثغرة الـ SNI / Bug Host (خاص بنجمة 6 إنوي)") },
                    placeholder = { Text("m.facebook.com") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                // اقتراحات سريعة لثغرات *6 إنوي
                Text("ثغرات سريعة لعرض *6 إنوي:", color = TextSecondary, fontSize = 11.sp)
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    items(MOROCCAN_STAR_6_BUG_HOSTS) { bugHost ->
                        Surface(
                            color = if (sniHost == bugHost.host) CyberBlue.copy(alpha = 0.3f) else DarkSurface,
                            shape = RoundedCornerShape(8.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (sniHost == bugHost.host) CyberBlue else CardBorder),
                            modifier = Modifier.clickable {
                                sniHost = bugHost.host
                                if (portText == "1080" || portText == "8080") {
                                    portText = "443"
                                }
                            }
                        ) {
                            Text(
                                text = bugHost.name,
                                color = if (sniHost == bugHost.host) CyberBlueLight else TextPrimary,
                                fontSize = 11.sp,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = dns,
                    onValueChange = { dns = it },
                    label = { Text("خادم DNS") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = CardBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val port = portText.toIntOrNull() ?: 443
                    val newProfile = VpnProfile(
                        id = System.currentTimeMillis().toString(),
                        name = name.ifBlank { "Inwi6 VPS الخاص بي" },
                        host = host.ifBlank { "187.77.168.45" },
                        port = port,
                        protocol = ProxyProtocol.VLESS,
                        dns = dns.ifBlank { "8.8.8.8" },
                        sniHost = sniHost.trim().ifBlank { "m.facebook.com" },
                        uuid = uuid.trim().ifBlank { "5ca53c7d-a947-4191-b98d-16ff5cdbd315" },
                        path = path.trim().ifBlank { "/morocco6" },
                        transport = "ws"
                    )
                    onSave(newProfile)
                },
                colors = ButtonDefaults.buttonColors(containerColor = CyberBlue),
                modifier = Modifier.testTag("save_custom_proxy_button")
            ) {
                Text("حفظ وتعيين", color = Color.White)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("إلغاء", color = TextMuted)
            }
        },
        containerColor = DarkSurfaceElevated
    )
}

/**
 * دالة مساعدة لتشغيل خدمة الـ VPN في المقدمة Foreground
 */
private fun startVpnService(context: Context, profile: VpnProfile) {
    val intent = Intent(context, LocalVpnService::class.java).apply {
        action = LocalVpnService.ACTION_CONNECT
        putExtra(LocalVpnService.EXTRA_HOST, profile.host)
        putExtra(LocalVpnService.EXTRA_PORT, profile.port)
        putExtra(LocalVpnService.EXTRA_NAME, profile.name)
        putExtra(LocalVpnService.EXTRA_PROTOCOL, profile.protocol.name)
        putExtra(LocalVpnService.EXTRA_SNI_HOST, profile.sniHost)
        putExtra(LocalVpnService.EXTRA_DNS, profile.dns)
        putExtra(LocalVpnService.EXTRA_UUID, profile.uuid)
        putExtra(LocalVpnService.EXTRA_PATH, profile.path)
    }
    ContextCompat.startForegroundService(context, intent)
}

/**
 * دالة مساعدة لإرسال إشارة إيقاف لخدمة الـ VPN
 */
private fun stopVpnService(context: Context) {
    val intent = Intent(context, LocalVpnService::class.java).apply {
        action = LocalVpnService.ACTION_DISCONNECT
    }
    context.startService(intent)
}
