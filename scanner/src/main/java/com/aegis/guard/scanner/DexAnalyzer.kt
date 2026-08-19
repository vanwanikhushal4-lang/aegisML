package com.aegis.guard.scanner

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class DexAnalysisResult(
    val isValid: Boolean,
    val stringCount: Int,
    val suspiciousFindings: List<String>
)

object DexAnalyzer {

    private val SUSPICIOUS_PATTERNS = listOf(
        "content://sms",                 // reads the SMS inbox
        "content://call_log",            // reads the call log
        "Ljava/lang/ProcessBuilder;",    // spawns a process / shell
        "Ldalvik/system/DexClassLoader;",// loads code not shipped in the APK
        "android/telephony/SmsManager"   // sends SMS from code
    )

    private val CARRY = SUSPICIOUS_PATTERNS.maxOf { it.length } - 1
    private const val CHUNK = 512 * 1024
    private const val MAX_SCAN_BYTES = 12 * 1024 * 1024
    private const val DEX_HEADER_SIZE = 112
    private const val STRING_IDS_SIZE_OFFSET = 56

    private val INVALID = DexAnalysisResult(isValid = false, stringCount = 0, suspiciousFindings = emptyList())

    fun analyzeApk(apkPath: String): DexAnalysisResult {
        val file = File(apkPath)
        if (!file.exists() || !file.canRead()) return INVALID

        return try {
            val entries = HardenedZipReader.readApkEntries(file)
            val dexes = entries.filter { it.name.matches(Regex("classes\\d*\\.dex")) }
            if (dexes.isEmpty()) return INVALID

            val found = LinkedHashSet<String>()
            var stringCount = 0
            var budget = MAX_SCAN_BYTES
            var sawValidDex = false

            for (entry in dexes) {
                if (found.size == SUSPICIOUS_PATTERNS.size || budget <= 0) break
                val input = ByteArrayInputStream(entry.data)
                val count = readHeader(input) ?: continue
                sawValidDex = true
                stringCount += count
                budget -= scan(input, budget, found)
            }

            if (sawValidDex) DexAnalysisResult(true, stringCount, found.toList()) else INVALID
        } catch (e: Exception) {
            INVALID
        }
    }

    private fun readHeader(input: InputStream): Int? {
        val header = ByteArray(DEX_HEADER_SIZE)
        var read = 0
        while (read < DEX_HEADER_SIZE) {
            val n = input.read(header, read, DEX_HEADER_SIZE - read)
            if (n == -1) break
            read += n
        }
        if (read < DEX_HEADER_SIZE) return null
        if (!String(header, 0, 4, Charsets.US_ASCII).startsWith("dex\n")) return null
        return ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).getInt(STRING_IDS_SIZE_OFFSET)
    }

    private fun scan(input: InputStream, budget: Int, found: MutableSet<String>): Int {
        val buf = ByteArray(CHUNK)
        var carry = ""
        var consumed = 0
        while (consumed < budget) {
            val n = input.read(buf, 0, minOf(CHUNK, budget - consumed))
            if (n <= 0) break
            consumed += n
            val text = carry + String(buf, 0, n, Charsets.ISO_8859_1)
            for (p in SUSPICIOUS_PATTERNS) if (p !in found && text.contains(p)) found.add(p)
            if (found.size == SUSPICIOUS_PATTERNS.size) break
            carry = if (text.length > CARRY) text.substring(text.length - CARRY) else text
        }
        return consumed
    }
}