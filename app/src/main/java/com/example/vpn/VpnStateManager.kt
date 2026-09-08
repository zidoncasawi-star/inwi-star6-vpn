package com.example.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * مدير حالة الـ VPN التفاعلي المشترك بين الخدمة وواجهة المستخدم
 */
object VpnStateManager {
    private val _status = MutableStateFlow(VpnStatus.DISCONNECTED)
    val status: StateFlow<VpnStatus> = _status.asStateFlow()

    private val _activeProfile = MutableStateFlow<VpnProfile?>(null)
    val activeProfile: StateFlow<VpnProfile?> = _activeProfile.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats())
    val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private val _logMessages = MutableStateFlow<List<String>>(emptyList())
    val logMessages: StateFlow<List<String>> = _logMessages.asStateFlow()

    fun updateStatus(newStatus: VpnStatus) {
        _status.value = newStatus
    }

    fun setActiveProfile(profile: VpnProfile?) {
        _activeProfile.value = profile
    }

    fun updateStats(stats: TrafficStats) {
        _trafficStats.value = stats
    }

    fun addLog(msg: String) {
        val current = _logMessages.value.toMutableList()
        if (current.size > 80) current.removeAt(0)
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        current.add("[$timestamp] $msg")
        _logMessages.value = current
    }

    fun resetStats() {
        _trafficStats.value = TrafficStats()
    }
}
