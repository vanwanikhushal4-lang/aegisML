package com.aegis.guard.scanner

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.Inflater

data class ApkEntry(
    val name: String,
    val data: ByteArray,
    val isEncryptedFlag: Boolean,
    val size: Int
)

/**
 * Robust, zero-crash APK Zip archive reader.
 * Bypasses anti-analysis zip header tampering, fake encryption flags (0x0001),
 * and corrupted central directory metadata that cause java.util.zip.ZipFile to throw ZipException.
 */
object HardenedZipReader {

    fun readApkEntries(apkFile: File): List<ApkEntry> {
        if (!apkFile.exists() || !apkFile.canRead()) return emptyList()
        val entries = mutableListOf<ApkEntry>()

        try {
            val apkBytes = apkFile.readBytes()
            val buf = ByteBuffer.wrap(apkBytes).order(ByteOrder.LITTLE_ENDIAN)
            val len = apkBytes.size
            var pos = 0

            while (pos < len - 30) {
                // Local File Header Signature: 0x04034b50 ("PK\x03\x04")
                if (buf.getInt(pos) == 0x04034b50) {
                    val flags = buf.getShort(pos + 6).toInt() and 0xFFFF
                    val method = buf.getShort(pos + 8).toInt() and 0xFFFF
                    val cSize = buf.getInt(pos + 18)
                    val uSize = buf.getInt(pos + 22)
                    val nameLen = buf.getShort(pos + 26).toInt() and 0xFFFF
                    val extraLen = buf.getShort(pos + 28).toInt() and 0xFFFF

                    val nameStart = pos + 30
                    if (nameStart + nameLen <= len) {
                        val nameBytes = ByteArray(nameLen)
                        System.arraycopy(apkBytes, nameStart, nameBytes, 0, nameLen)
                        val name = String(nameBytes, Charsets.UTF_8)

                        val dataStart = nameStart + nameLen + extraLen
                        var data = ByteArray(0)

                        if (cSize > 0 && dataStart + cSize <= len) {
                            val compData = ByteArray(cSize)
                            System.arraycopy(apkBytes, dataStart, compData, 0, cSize)

                            if (method == 0) { // STORED
                                data = compData
                            } else if (method == 8) { // DEFLATED
                                try {
                                    val inflater = Inflater(true)
                                    inflater.setInput(compData)
                                    val baos = ByteArrayOutputStream(if (uSize > 0) uSize else cSize * 2)
                                    val tmp = ByteArray(4096)
                                    while (!inflater.finished()) {
                                        val count = inflater.inflate(tmp)
                                        if (count == 0) break
                                        baos.write(tmp, 0, count)
                                    }
                                    inflater.end()
                                    data = baos.toByteArray()
                                } catch (ex: Exception) {
                                    data = compData
                                }
                            }
                        }

                        entries.add(
                            ApkEntry(
                                name = name,
                                data = data,
                                isEncryptedFlag = (flags and 0x0001) != 0,
                                size = data.size
                            )
                        )
                    }
                    pos += 30 + nameLen + extraLen + (if (cSize > 0) cSize else 0)
                } else {
                    pos++
                }
            }
        } catch (e: Exception) {
            // Return whatever entries were successfully extracted
        }

        return entries
    }
}