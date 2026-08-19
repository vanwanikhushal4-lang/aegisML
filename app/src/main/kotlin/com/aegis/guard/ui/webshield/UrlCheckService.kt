package com.aegis.guard.ui.webshield

import android.content.Context
import android.net.Uri
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import javax.inject.Inject
import javax.inject.Singleton

data class UrlScanResult(
    val url: String,
    val isMalicious: Boolean,
    val threatType: ThreatType,
    val confidence: Confidence,
    val source: String,
    val scannedAt: Long = System.currentTimeMillis()
)

data class SmsLinkResult(
    val sender: String,
    val messageSnippet: String,
    val url: String,
    val scanResult: UrlScanResult
)

enum class ThreatType(val label: String, val description: String) {
    CLEAN("Clean", "No threats detected"),
    PHISHING("Phishing", "Designed to steal credentials"),
    MALWARE("Malware", "Distributes malicious software"),
    SOCIAL_ENGINEERING("Social Engineering", "Manipulates users into unsafe actions"),
    UNWANTED_SOFTWARE("Unwanted Software", "Installs potentially harmful software"),
    UNKNOWN("Unknown", "Unable to determine threat type")
}

enum class Confidence { HIGH, MEDIUM, LOW }

@Singleton
class UrlCheckService @Inject constructor(
    @ApplicationContext private val context: Context
) {
    // Known-bad domains for demo purposes (simulates real GSB response)
    private val knownBadDomains = setOf(
        "phishing-site.xyz", "malware-download.ru", "fake-bank-login.com",
        "steal-credentials.net", "free-crypto-hack.io", "suspicious-banking-site.xyz",
        "click-bait-virus.com", "trojan-download.org"
    )

    private val knownSuspiciousDomains = setOf(
        "bit.ly", "tinyurl.com", "t.co" // Shortened URLs — flag as unverified
    )

    /**
     * Check a URL for threats.
     * In production: replace this with a Retrofit call to POST /v1/threat/check-url
     */
    suspend fun checkUrl(rawUrl: String): UrlScanResult {
        // Simulate network latency
        delay((300..800).random().toLong())

        val normalizedUrl = rawUrl.trim().lowercase()
        val domain = extractDomain(normalizedUrl)

        return when {
            knownBadDomains.any { normalizedUrl.contains(it) } -> UrlScanResult(
                url = rawUrl,
                isMalicious = true,
                threatType = if (normalizedUrl.contains("phish") || normalizedUrl.contains("login") || normalizedUrl.contains("bank"))
                    ThreatType.PHISHING else ThreatType.MALWARE,
                confidence = Confidence.HIGH,
                source = "AEGIS Threat DB"
            )
            knownSuspiciousDomains.any { domain == it } -> UrlScanResult(
                url = rawUrl,
                isMalicious = false,
                threatType = ThreatType.UNKNOWN,
                confidence = Confidence.LOW,
                source = "AEGIS Heuristics"
            )
            else -> UrlScanResult(
                url = rawUrl,
                isMalicious = false,
                threatType = ThreatType.CLEAN,
                confidence = Confidence.HIGH,
                source = "Google Safe Browsing"
            )
        }
    }

    private fun extractDomain(url: String): String {
        return try {
            val withScheme = if (!url.startsWith("http")) "https://$url" else url
            Uri.parse(withScheme).host ?: url
        } catch (e: Exception) {
            url
        }
    }

    /**
     * Scan SMS messages for embedded URLs.
     * In production: READ_SMS permission must be granted first.
     * Returns fake demo data when permission not granted.
     */
    suspend fun scanSmsLinks(): List<SmsLinkResult> {
        delay(1200)
        // Demo data — real implementation reads from ContentResolver("content://sms/inbox")
        return listOf(
            SmsLinkResult(
                sender = "+91-99XXXX1234",
                messageSnippet = "Your account is suspended. Verify now:",
                url = "http://fake-bank-login.com/verify",
                scanResult = UrlScanResult(
                    url = "http://fake-bank-login.com/verify",
                    isMalicious = true,
                    threatType = ThreatType.PHISHING,
                    confidence = Confidence.HIGH,
                    source = "AEGIS Threat DB"
                )
            ),
            SmsLinkResult(
                sender = "VM-HDFCBK",
                messageSnippet = "Your OTP is 482910. Do not share with anyone.",
                url = "https://hdfcbank.com",
                scanResult = UrlScanResult(
                    url = "https://hdfcbank.com",
                    isMalicious = false,
                    threatType = ThreatType.CLEAN,
                    confidence = Confidence.HIGH,
                    source = "Google Safe Browsing"
                )
            ),
            SmsLinkResult(
                sender = "+91-88XXXX5678",
                messageSnippet = "Win FREE iPhone! Click here now:",
                url = "http://free-crypto-hack.io/iphone",
                scanResult = UrlScanResult(
                    url = "http://free-crypto-hack.io/iphone",
                    isMalicious = true,
                    threatType = ThreatType.SOCIAL_ENGINEERING,
                    confidence = Confidence.HIGH,
                    source = "AEGIS Threat DB"
                )
            )
        )
    }
}
