package com.aegis.guard.scanner

import java.io.File
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.log2

/**
 * Result of forensic structural APK analysis for evasion, packers, and hidden assets.
 */
data class StructuralAnalysisResult(
    val isPackedThreat: Boolean = false,
    val structuralScore: Int = 0,
    val reasons: List<String> = emptyList(),
    val maxAssetEntropy: Double = 0.0,
    val isZipTampered: Boolean = false,
    val isThinDex: Boolean = false,
    val hasEncryptedAsset: Boolean = false,
    val hasWebviewPhishing: Boolean = false
)

/**
 * Forensic Structural Packer & Anti-Analysis Detector for in-the-wild evasive malware.
 * Uses HardenedZipReader to bypass fake encryption headers and corrupt CEN tables.
 */
@Singleton
class StructuralPackerDetector @Inject constructor() {

    companion object {
        private const val MAX_THIN_DEX_SIZE_BYTES = 40_000L // 40 KB
        private const val MIN_ENCRYPTED_ASSET_SIZE_BYTES = 50_000L // 50 KB
        private const val HIGH_ENTROPY_THRESHOLD = 7.80
    }

    /**
     * Inspects an APK file on disk for structural packer evasion patterns.
     */
    fun analyze(apkPath: String?): StructuralAnalysisResult {
        if (apkPath.isNullOrBlank()) return StructuralAnalysisResult()
        val apkFile = File(apkPath)
        if (!apkFile.exists() || !apkFile.canRead()) return StructuralAnalysisResult()

        var totalDexSize = 0L
        var hasNativeLib = false
        var hasEncryptedAsset = false
        var hasWebviewPhishing = false
        var encryptedAssetName = ""
        var maxAssetEntropy = 0.0
        var zipTampered = false
        var htmlCardMentions = 0
        val reasons = mutableListOf<String>()

        val entries = HardenedZipReader.readApkEntries(apkFile)

        for (entry in entries) {
            val name = entry.name
            val data = entry.data

            if (entry.isEncryptedFlag) {
                zipTampered = true
            }

            when {
                name.endsWith(".dex", ignoreCase = true) -> {
                    totalDexSize += data.size
                }
                name.endsWith(".so", ignoreCase = true) || name.startsWith("lib/", ignoreCase = true) -> {
                    hasNativeLib = true
                }
                name.startsWith("assets/", ignoreCase = true) -> {
                    if (data.size > MIN_ENCRYPTED_ASSET_SIZE_BYTES) {
                        val headerBytes = data.take(16).toByteArray()
                        val magic = if (headerBytes.isNotEmpty()) String(headerBytes, Charsets.ISO_8859_1) else ""

                        val sampleBytes = data.take(8192).toByteArray()
                        val entropy = computeEntropy(sampleBytes, sampleBytes.size)
                        if (entropy > maxAssetEntropy) maxAssetEntropy = entropy

                        if (entropy >= HIGH_ENTROPY_THRESHOLD ||
                            magic.startsWith("\u007fEPDATA") ||
                            magic.startsWith("dex\n") ||
                            magic.startsWith("\u007fELF")
                        ) {
                            hasEncryptedAsset = true
                            encryptedAssetName = name
                        }
                    } else if (name.endsWith(".html", ignoreCase = true) || name.endsWith(".js", ignoreCase = true)) {
                        val content = String(data, Charsets.UTF_8).lowercase()
                        val cardCount = content.split("card").size - 1
                        if (cardCount >= 5) {
                            hasWebviewPhishing = true
                            htmlCardMentions = cardCount
                        }
                    }
                }
            }
        }

        var score = 0
        val isThinDex = totalDexSize in 1..MAX_THIN_DEX_SIZE_BYTES && hasNativeLib

        if (hasEncryptedAsset) {
            score += 45
            reasons.add("High-Entropy Encrypted Asset Blob ($encryptedAssetName, entropy=${"%.2f".format(maxAssetEntropy)})")
        }
        if (isThinDex) {
            score += 30
            reasons.add("Thin DEX Loader Stub (${totalDexSize / 1024} KB) paired with Native .so Unpacker")
        }
        if (hasWebviewPhishing) {
            score += 35
            reasons.add("Local WebView Financial Phishing Template ($htmlCardMentions card references)")
        }
        if (zipTampered) {
            score += 35
            reasons.add("Archive Header Anti-Analysis Tampering (Fake 0x0001 Encryption Flag)")
        }

        val finalScore = score.coerceIn(0, 100)
        return StructuralAnalysisResult(
            isPackedThreat = finalScore >= 60,
            structuralScore = finalScore,
            reasons = reasons,
            maxAssetEntropy = maxAssetEntropy,
            isZipTampered = zipTampered,
            isThinDex = isThinDex,
            hasEncryptedAsset = hasEncryptedAsset,
            hasWebviewPhishing = hasWebviewPhishing
        )
    }

    fun computeEntropy(data: ByteArray, length: Int): Double {
        if (length <= 0) return 0.0
        val freq = IntArray(256)
        for (i in 0 until length) {
            freq[data[i].toInt() and 0xFF]++
        }
        var entropy = 0.0
        val lenDouble = length.toDouble()
        for (count in freq) {
            if (count > 0) {
                val p = count.toDouble() / lenDouble
                entropy -= p * log2(p)
            }
        }
        return entropy
    }
}