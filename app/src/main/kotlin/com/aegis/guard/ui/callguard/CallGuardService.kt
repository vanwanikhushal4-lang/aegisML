package com.aegis.guard.ui.callguard

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import javax.inject.Inject
import javax.inject.Singleton

// ─── Data Models ──────────────────────────────────────────────────────────────

enum class CallRisk {
    SAFE, SUSPECTED_SPAM, CONFIRMED_SPAM, SCAM, ROBOCALL, TELEMARKETER
}

data class CallRiskInfo(
    val number: String,
    val risk: CallRisk,
    val label: String,           // e.g. "Telemarketer", "Bank Scam"
    val reportCount: Int,        // How many users reported this number
    val confidence: Int,         // 0–100
    val carrier: String? = null
)

data class BlockedCallEntry(
    val number: String,
    val displayName: String,
    val callRisk: CallRisk,
    val riskLabel: String,
    val blockedAt: Long,
    val callDurationMs: Long = 0 // 0 = auto-blocked before connecting
)

data class CallGuardStats(
    val totalCallsScreened: Int = 0,
    val spamBlocked: Int = 0,
    val scamBlocked: Int = 0,
    val robocallsBlocked: Int = 0
)

@Singleton
class CallGuardService @Inject constructor(
    @ApplicationContext private val context: Context
) {
    // Known spam numbers for demo — in production this comes from backend
    private val spamDatabase = mapOf(
        "+919XXXXXXXXX" to CallRiskInfo("+919XXXXXXXXX", CallRisk.SCAM, "Bank Scam", 1423, 98),
        "1800XXXXXXX"  to CallRiskInfo("1800XXXXXXX",  CallRisk.TELEMARKETER, "Insurance Telemarketer", 867, 91),
        "+18885551234" to CallRiskInfo("+18885551234", CallRisk.ROBOCALL, "Auto Warranty Robocall", 5221, 99),
        "+14155552671" to CallRiskInfo("+14155552671", CallRisk.SUSPECTED_SPAM, "Suspected Spam", 34, 62),
        "+919876543210" to CallRiskInfo("+919876543210", CallRisk.CONFIRMED_SPAM, "Loan Scam", 3102, 97),
    )

    suspend fun checkNumber(number: String): CallRiskInfo {
        delay((200..600).random().toLong())
        return spamDatabase[number] ?: CallRiskInfo(
            number = number,
            risk = CallRisk.SAFE,
            label = "No threats found",
            reportCount = 0,
            confidence = 95
        )
    }

    fun getBlockedCallHistory(): List<BlockedCallEntry> {
        return listOf(
            BlockedCallEntry("+919876543210", "+91 98765 43210", CallRisk.SCAM, "Loan Scam", System.currentTimeMillis() - 3_600_000),
            BlockedCallEntry("+18885551234", "+1 (888) 555-1234", CallRisk.ROBOCALL, "Auto Warranty Robocall", System.currentTimeMillis() - 7_200_000),
            BlockedCallEntry("1800XXXXXXX", "1800-XXXXXXX", CallRisk.TELEMARKETER, "Insurance Telemarketer", System.currentTimeMillis() - 86_400_000),
            BlockedCallEntry("+14155552671", "+1 (415) 555-2671", CallRisk.SUSPECTED_SPAM, "Suspected Spam", System.currentTimeMillis() - 172_800_000),
            BlockedCallEntry("+919XXXXXXXXX", "+91 9X XXXX XXXX", CallRisk.SCAM, "Bank Scam", System.currentTimeMillis() - 259_200_000),
        )
    }

    fun getStats(): CallGuardStats = CallGuardStats(
        totalCallsScreened = 1_847,
        spamBlocked = 42,
        scamBlocked = 17,
        robocallsBlocked = 89
    )
}
