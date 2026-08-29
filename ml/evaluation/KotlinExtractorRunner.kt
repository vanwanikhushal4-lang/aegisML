package com.aegis.guard.scanner

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.regex.Pattern
import java.util.zip.Inflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

object KotlinExtractorRunner {

    const val NUM_FEATURES = 92

    val DANGEROUS_PERMS = mapOf(
        "android.permission.READ_SMS" to 0,
        "android.permission.RECEIVE_SMS" to 1,
        "android.permission.SEND_SMS" to 2,
        "android.permission.READ_CALL_LOG" to 3,
        "android.permission.WRITE_CALL_LOG" to 4,
        "android.permission.READ_CONTACTS" to 5,
        "android.permission.WRITE_CONTACTS" to 6,
        "android.permission.ACCESS_FINE_LOCATION" to 7,
        "android.permission.ACCESS_COARSE_LOCATION" to 8,
        "android.permission.RECORD_AUDIO" to 9,
        "android.permission.CAMERA" to 10,
        "android.permission.SYSTEM_ALERT_WINDOW" to 11,
        "android.permission.READ_PHONE_STATE" to 12,
        "android.permission.PROCESS_OUTGOING_CALLS" to 13,
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 14,
        "android.permission.BIND_DEVICE_ADMIN" to 15,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 16,
        "android.permission.INSTALL_PACKAGES" to 17,
        "android.permission.QUERY_ALL_PACKAGES" to 18,
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 19,
        "android.permission.USE_BIOMETRIC" to 20,
        "android.permission.WRITE_SETTINGS" to 21,
        "android.permission.GET_ACCOUNTS" to 22
    )

    val TRUSTED_CERT_SHA256_SET = setOf(
        // Google LLC Platform & App Keys
        "3184771213aaa571eb74bc34f461cf694aa552a0d05a166053661fe334dc2f3a",
        "38918a453d07199354f8b19af05ec6562ced5788d60a8c38548b5dbf6670a3b4",
        "f0fd6c5ec410f2157d093b8099e04b609e2cb4ef60e445d4e83f16334f5d82dc",
        // Samsung Electronics / Knox One UI Keys
        "9b9ebef87d4c7dcc740812f280e026df5db094f510d2af443cb42789030e30c9",
        "ae3bf39f22975896a3ddcc7f4084af538a48026c6cfdc4b62cf8a4778f424e99",
        "58e3e81e0e7e29401e18d102d3f03e1826b4f44060f687e844243c4e09ec1638",
        // Xiaomi / MIUI / HyperOS Platform Keys
        "f9e21ac0410b6d48162ba288e1a7086f2b819b6289489a39e809cdc534d89332",
        "1bd4f1422fde8b0c3b877e99ffe0ed5b8944c5c8563ba1eaaf506d59d577798b",
        "287e07662c1d06371cf792518e1b6f005c331a9c3756dfc1e55099351e06c7e2",
        // OnePlus (OxygenOS) Platform Keys
        "eb485a89673ba2cd621dc52ae3d2726af4370e42bf9f24b0b5158f75a328e24f",
        "6465dc41094038a8e1039989f6645367b140669b33a5796a84d4361546944e89",
        // OPPO / Realme (ColorOS / Realme UI) Platform Keys
        "0da273d28326a60aaabe1c53fa2bc1d700e01f1795e49317657972db72f65212",
        "c06d3f3371f8b17b498ec05ba7155726ba1db15ba699451344d163e4d2bc1347",
        "e43a71a5092101f6a161af1630bb7ff1ddde3a7633e21d6006466ebd413b2b4e",
        // Huawei / Honor (HarmonyOS / EMUI) Platform Keys
        "dd5a2a9b7c7b9e4c447b2d6ac2ccf2900b86d32e15ddb0c742d2be8ccc351518",
        "bf17d057a70a8d46a6f6df600e0544425aa1453270424d31f602d693213e42fd",
        // Vivo / iQOO (FuntouchOS / OriginOS) Platform Keys
        "832aae9a7368771d4d2ee93fd572be681a2d12e3d4b358b1c65053290d50b560",
        "1954a9307d2199c05e22036400c3cd9e80e2995b93fe6d309ee1d6150994fb63",
        // Indian Banking / UPI / NPCI
        "102d059606fc9859dbc7029e95914132f248f4952c1d48ca3dc7bee65d7db606",
        "d2bbe55f4b3aa28780d761a144ab4b29e8e41c8fb47d4d44500c2688b6d49092",
        "c4436573c52e8964e52627048a1c97a80b7204eb0a696328fb68ef21199a0994"
    )

    data class ZipItem(val name: String, val data: ByteArray, val isEncryptedFlag: Boolean)

    data class ManifestData(
        var packageName: String = "",
        var targetSdkVersion: Int = 33,
        var minSdkVersion: Int = 21,
        val permissions: MutableSet<String> = mutableSetOf(),
        val activities: MutableList<String> = mutableListOf(),
        val services: MutableList<String> = mutableListOf(),
        val receivers: MutableList<String> = mutableListOf(),
        var hasBootReceiver: Boolean = false,
        var hasSmsReceiver: Boolean = false,
        var hasForegroundService: Boolean = false,
        var hasLauncherActivity: Boolean = false,
        var appLabel: String = ""
    )

    private fun computeShannonEntropy(data: ByteArray, length: Int): Double {
        if (length <= 0) return 0.0
        val freq = IntArray(256)
        for (i in 0 until length) {
            freq[data[i].toInt() and 0xFF]++
        }
        var entropy = 0.0
        val lenD = length.toDouble()
        for (count in freq) {
            if (count > 0) {
                val p = count.toDouble() / lenD
                entropy -= p * (Math.log(p) / Math.log(2.0))
            }
        }
        return entropy
    }

    private fun readApkEntries(file: File): List<ZipItem> {
        val items = mutableListOf<ZipItem>()
        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val bytes = try {
                        zip.getInputStream(entry).use { it.readBytes() }
                    } catch (e: Exception) {
                        ByteArray(0)
                    }
                    items.add(ZipItem(entry.name, bytes, false))
                }
            }
            return items
        } catch (ex: Exception) {
            return readApkHardened(file)
        }
    }

    private fun readApkHardened(file: File): List<ZipItem> {
        val entries = mutableListOf<ZipItem>()
        try {
            val apkBytes = file.readBytes()
            val buf = ByteBuffer.wrap(apkBytes).order(ByteOrder.LITTLE_ENDIAN)
            var pos = 0
            val len = apkBytes.size

            while (pos < len - 30) {
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
                        val name = String(nameBytes, StandardCharsets.UTF_8)

                        val dataStart = nameStart + nameLen + extraLen
                        var data = ByteArray(0)

                        if (cSize > 0 && dataStart + cSize <= len) {
                            val compData = ByteArray(cSize)
                            System.arraycopy(apkBytes, dataStart, compData, 0, cSize)

                            if (method == 0) {
                                data = compData
                            } else if (method == 8) {
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
                                } catch (ignored: Exception) {}
                            }
                        }

                        val isEncrypted = (flags and 0x0001) != 0
                        entries.add(ZipItem(name, data, isEncrypted))
                    }
                    pos += 30 + nameLen + extraLen + (if (cSize > 0) cSize else 0)
                } else {
                    pos++
                }
            }
        } catch (ignored: Exception) {}
        return entries
    }

    private fun parseAxml(axml: ByteArray): ManifestData {
        val data = ManifestData()
        try {
            val buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN)
            if (buf.remaining() < 8) return data

            buf.getInt() // magic
            buf.getInt() // fileSize

            val stringPool = mutableListOf<String>()

            while (buf.hasRemaining()) {
                val chunkPos = buf.position()
                if (buf.remaining() < 8) break
                val chunkType = buf.getInt()
                val chunkSize = buf.getInt()
                if (chunkSize <= 0 || chunkPos + chunkSize > axml.size) break

                if (chunkType == 0x001C0001) { // String Pool
                    val stringCount = buf.getInt()
                    buf.getInt() // styleCount
                    val flags = buf.getInt()
                    val stringsStart = buf.getInt()
                    buf.getInt() // stylesStart

                    val offsets = IntArray(stringCount) { buf.getInt() }
                    val poolStart = chunkPos + stringsStart
                    val isUtf8 = (flags and (1 shl 8)) != 0

                    for (i in 0 until stringCount) {
                        val pos = poolStart + offsets[i]
                        if (pos < axml.size) {
                            buf.position(pos)
                            if (isUtf8) {
                                buf.get()
                                val byteLen = buf.get().toInt() and 0xFF
                                val strBytes = ByteArray(byteLen)
                                buf.get(strBytes)
                                stringPool.add(String(strBytes, StandardCharsets.UTF_8))
                            } else {
                                val len = buf.getShort().toInt() and 0xFFFF
                                val strBytes = ByteArray(len * 2)
                                buf.get(strBytes)
                                stringPool.add(String(strBytes, StandardCharsets.UTF_16LE))
                            }
                        } else {
                            stringPool.add("")
                        }
                    }
                } else if (chunkType == 0x00100102) { // START_TAG
                    buf.getInt() // line
                    buf.getInt() // comment
                    buf.getInt() // ns
                    val nameIdx = buf.getInt()
                    val tagName = if (nameIdx in stringPool.indices) stringPool[nameIdx] else ""

                    buf.getShort()
                    buf.getShort()
                    val attrCount = buf.getShort().toInt() and 0xFFFF
                    buf.getShort()
                    buf.getShort()
                    buf.getShort()

                    val attrs = mutableMapOf<String, Any>()
                    for (a in 0 until attrCount) {
                        buf.getInt()
                        val aNameIdx = buf.getInt()
                        val aRawVal = buf.getInt()
                        val aType = buf.getInt()
                        val aData = buf.getInt()

                        val aName = if (aNameIdx in stringPool.indices) stringPool[aNameIdx] else ""
                        val aStrVal = if (aRawVal in stringPool.indices) stringPool[aRawVal] else ""

                        if (aType == 0x03) {
                            attrs[aName] = aStrVal
                        } else if (aType == 0x10 || aType == 0x11 || aType == 0x12) {
                            attrs[aName] = aData
                        } else {
                            attrs[aName] = if (aStrVal.isNotEmpty()) aStrVal else aData
                        }
                    }

                    when (tagName) {
                        "manifest" -> {
                            val pkg = attrs["package"]
                            if (pkg is String) data.packageName = pkg.lowercase()
                        }
                        "uses-sdk" -> {
                            val tSdk = attrs["targetSdkVersion"]
                            if (tSdk is Int) data.targetSdkVersion = tSdk
                            val mSdk = attrs["minSdkVersion"]
                            if (mSdk is Int) data.minSdkVersion = mSdk
                        }
                        "uses-permission", "permission" -> {
                            val pName = attrs["name"]
                            if (pName is String) data.permissions.add(pName)
                        }
                        "activity", "activity-alias" -> {
                            val actName = attrs["name"]
                            if (actName is String) data.activities.add(actName)
                        }
                        "service" -> {
                            val srvName = attrs["name"]
                            if (srvName is String) data.services.add(srvName)
                        }
                        "receiver" -> {
                            val recName = attrs["name"]
                            if (recName is String) data.receivers.add(recName)
                        }
                        "action" -> {
                            val act = attrs["name"]
                            if (act is String) {
                                if (act == "android.intent.action.BOOT_COMPLETED") data.hasBootReceiver = true
                                if (act == "android.provider.Telephony.SMS_RECEIVED" || act == "android.provider.Telephony.SMS_DELIVER") data.hasSmsReceiver = true
                                if (act == "android.intent.action.MAIN") data.hasLauncherActivity = true
                            }
                        }
                        "application" -> {
                            val label = attrs["label"]
                            if (label is String) data.appLabel = label
                        }
                    }
                }
                buf.position(chunkPos + chunkSize)
            }
        } catch (ignored: Exception) {}
        return data
    }

    fun extractFromApk(targetPath: String, provenance: String): FloatArray {
        val vec = FloatArray(NUM_FEATURES)
        val file = File(targetPath)
        if (!file.exists()) {
            throw IllegalArgumentException("Target file not found: $targetPath")
        }

        val apkFiles = if (file.isDirectory) {
            file.listFiles { f -> f.name.endsWith(".apk") }?.toList() ?: emptyList()
        } else {
            listOf(file)
        }

        if (apkFiles.isEmpty()) {
            throw IllegalArgumentException("No APK files found at: $targetPath")
        }

        val dexStrings = mutableSetOf<String>()
        var manifest = ManifestData()
        var totalDexSize = 0L
        var hasNativeLib = false
        var maxAssetEntropy = 0.0
        var htmlCardMentions = 0
        var zipTampered = false
        var arscContent = ""

        val targets = listOf(
            "content://sms", "content://telephony/sms", "content://call_log", "content://contacts",
            "com.android.contacts", "android.telephony.SmsManager", "sendTextMessage", "SmsManager",
            "java.lang.ProcessBuilder", "ProcessBuilder", "Runtime.getRuntime().exec", "Runtime.exec",
            "dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader",
            "java.lang.reflect.Method.invoke", "Method.invoke", "java.net.Socket", "Socket(", "connectSocket",
            "getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber",
            "/system/bin/sh", "chmod 777", "/system/xbin/su", "which su",
            "javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding",
            "android.util.Base64.decode", "Base64.decode", "Base64",
            "/system/app/Superuser.apk", "test-keys", "busybox",
            "AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo",
            "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent",
            "SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"
        )

        for (apkFile in apkFiles) {
            val entries = readApkEntries(apkFile)
            for (item in entries) {
                val name = item.name
                val bytes = item.data
                if (item.isEncryptedFlag) zipTampered = true

                if (name.endsWith(".dex")) {
                    totalDexSize += bytes.size
                    val content = String(bytes, StandardCharsets.ISO_8859_1)
                    for (t in targets) {
                        if (content.contains(t)) {
                            dexStrings.add(t)
                        }
                    }
                    if (Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b").matcher(content).find()) {
                        dexStrings.add("RAW_C2_IP")
                    }
                } else if (name == "AndroidManifest.xml" && manifest.packageName.isEmpty()) {
                    manifest = parseAxml(bytes)
                } else if (name == "resources.arsc") {
                    arscContent = String(bytes, StandardCharsets.ISO_8859_1).lowercase()
                } else if (name.endsWith(".so") || name.startsWith("lib/")) {
                    hasNativeLib = true
                } else if (name.startsWith("assets/")) {
                    if (bytes.size > 50000) {
                        val sampleLen = Math.min(bytes.size, 8192)
                        val ent = computeShannonEntropy(bytes, sampleLen)
                        if (ent > maxAssetEntropy) maxAssetEntropy = ent
                    }
                    if (name.endsWith(".html") || name.endsWith(".js")) {
                        val text = String(bytes, StandardCharsets.UTF_8).lowercase()
                        val cardCount = text.split("card").size - 1
                        if (cardCount >= 5) htmlCardMentions += cardCount
                    }
                }
            }
        }

        // 1. Permissions (0-29)
        var dangCount = 0
        for (perm in manifest.permissions) {
            val idx = DANGEROUS_PERMS[perm]
            if (idx != null) {
                vec[idx] = 1.0f
                dangCount++
            }
        }

        val readSms = (vec[0] == 1.0f || vec[1] == 1.0f)
        val sendSms = (vec[2] == 1.0f)
        if (readSms && sendSms) vec[23] = 1.0f
        if (vec[9] == 1.0f && (vec[7] == 1.0f || vec[8] == 1.0f) && vec[10] == 1.0f) vec[24] = 1.0f
        if (vec[11] == 1.0f && vec[14] == 1.0f) vec[25] = 1.0f
        if (vec[3] == 1.0f && readSms && vec[5] == 1.0f) vec[26] = 1.0f

        vec[27] = Math.min(dangCount.toFloat() / 20.0f, 1.0f)
        vec[28] = Math.min(manifest.permissions.size.toFloat() / 60.0f, 1.0f)
        vec[29] = if (manifest.permissions.any { it.contains("signature", ignoreCase = true) }) 1.0f else 0.0f

        // 2. DEX Usage (30-48)
        var dexSuspCount = 0
        fun checkDex(patterns: List<String>, idx: Int) {
            if (patterns.any { dexStrings.contains(it) }) {
                vec[idx] = 1.0f
                dexSuspCount++
            }
        }

        checkDex(listOf("content://sms", "content://telephony/sms"), 30)
        checkDex(listOf("content://call_log"), 31)
        checkDex(listOf("content://contacts", "com.android.contacts"), 32)
        checkDex(listOf("android.telephony.SmsManager", "sendTextMessage", "SmsManager"), 33)
        checkDex(listOf("java.lang.ProcessBuilder", "ProcessBuilder"), 34)
        checkDex(listOf("Runtime.getRuntime().exec", "Runtime.exec"), 35)
        checkDex(listOf("dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"), 36)
        checkDex(listOf("java.lang.reflect.Method.invoke", "Method.invoke"), 37)
        checkDex(listOf("java.net.Socket", "Socket(", "connectSocket"), 38)
        checkDex(listOf("getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber"), 39)
        checkDex(listOf("/system/bin/sh", "chmod 777", "/system/xbin/su", "which su"), 40)
        checkDex(listOf("javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"), 41)
        checkDex(listOf("android.util.Base64.decode", "Base64.decode", "Base64"), 42)
        checkDex(listOf("/system/app/Superuser.apk", "test-keys", "busybox"), 43)
        checkDex(listOf("RAW_C2_IP"), 44)
        checkDex(listOf("AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo"), 45)
        checkDex(listOf("AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent"), 46)
        checkDex(listOf("SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"), 47)

        vec[48] = Math.min(dexSuspCount.toFloat() / 15.0f, 1.0f)

        // 3. Manifest Structure (49-60)
        val actCount = Math.max(manifest.activities.size, 1)
        val srvCount = manifest.services.size
        val recCount = manifest.receivers.size
        val totComp = actCount + srvCount + recCount
        vec[49] = Math.min(actCount.toFloat() / 20.0f, 1.0f)
        vec[50] = Math.min(srvCount.toFloat() / 10.0f, 1.0f)
        vec[51] = Math.min(recCount.toFloat() / 10.0f, 1.0f)
        vec[52] = if (manifest.hasBootReceiver || manifest.permissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")) 1.0f else 0.0f
        vec[53] = if (manifest.hasSmsReceiver || manifest.permissions.contains("android.permission.RECEIVE_SMS")) 1.0f else 0.0f
        vec[54] = if (manifest.hasForegroundService || manifest.permissions.contains("android.permission.FOREGROUND_SERVICE")) 1.0f else 0.0f
        vec[55] = vec[14]
        vec[56] = vec[15]
        vec[57] = vec[11]
        vec[58] = if (manifest.hasLauncherActivity || actCount > 0) 1.0f else 0.0f
        vec[59] = Math.min(totComp.toFloat() / 50.0f, 1.0f)
        vec[60] = 0.50f

        // 4. Certificates (61-66)
        var isDebug = false
        var isKnownPub = false
        var certCount = 0
        for (apkFile in apkFiles) {
            val entries = readApkEntries(apkFile)
            for (item in entries) {
                if (item.name.startsWith("META-INF/") && (item.name.endsWith(".RSA") || item.name.endsWith(".DSA") || item.name.endsWith(".EC"))) {
                    try {
                        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
                        val certList = cf.generateCertificates(java.io.ByteArrayInputStream(item.data))
                        certCount += certList.size
                        val md = java.security.MessageDigest.getInstance("SHA-256")
                        for (c in certList) {
                            val xc = c as? java.security.cert.X509Certificate ?: continue
                            val subj = xc.subjectDN.name.lowercase()
                            val issuer = xc.issuerDN.name.lowercase()
                            if (subj.contains("debug") || issuer.contains("debug") || subj.contains("test-keys") || subj.contains("testkey")) {
                                isDebug = true
                            } else if (!isDebug) {
                                val sha256 = md.digest(xc.encoded).joinToString("") { "%02x".format(it) }.lowercase()
                                if (sha256 in TRUSTED_CERT_SHA256_SET) {
                                    isKnownPub = true
                                }
                            }
                        }
                    } catch (ignored: Exception) {}
                }
            }
        }
        vec[61] = if (isDebug) 1.0f else 0.0f
        vec[63] = if (isKnownPub && !isDebug) 1.0f else 0.0f
        vec[64] = 0.50f
        vec[66] = Math.min(certCount.toFloat() / 5.0f, 1.0f)

        // 5. Provenance & Metadata (67-79)
        when (provenance.uppercase()) {
            "SYSTEM_IMAGE" -> vec[67] = 1.0f
            "UPDATED_SYSTEM_APP" -> vec[68] = 1.0f
            "VERIFIED_STORE" -> vec[69] = 1.0f
            "CONFIRMED_LOCAL_APK" -> vec[70] = 1.0f
            "DOWNLOADED_APK" -> vec[71] = 1.0f
            "RESTORED_OEM" -> vec[72] = 1.0f
            else -> vec[73] = 1.0f // UNKNOWN
        }

        // UNKNOWN is strictly distinct from DOWNLOADED/SIDELOADED
        val isUntrusted = (vec[71] == 1.0f) || (vec[70] == 1.0f && vec[63] == 0.0f)
        val targetSdk = manifest.targetSdkVersion
        val minSdk = manifest.minSdkVersion
        val pkgName = manifest.packageName

        vec[74] = Math.min(targetSdk.toFloat() / 35.0f, 1.0f)
        vec[75] = if (targetSdk <= 22) 1.0f else 0.0f
        vec[76] = if (targetSdk <= 28) 1.0f else 0.0f
        vec[77] = Math.min(minSdk.toFloat() / 35.0f, 1.0f)

        val isSystem = (vec[67] == 1.0f || vec[68] == 1.0f)
        val label = (manifest.appLabel + " " + arscContent).lowercase()
        val brands = listOf("google service", "google play", "system update", "google framework", "android system",
                            "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram")
        var impersonates = false
        if (!isSystem && vec[63] == 0.0f) {
            for (b in brands) {
                if (label.contains(b) && !pkgName.contains(b.split(" ")[0])) {
                    impersonates = true
                    break
                }
            }
        }
        vec[78] = if (impersonates) 1.0f else 0.0f

        val suspTokens = listOf("reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan")
        vec[79] = if (suspTokens.any { pkgName.contains(it) } && vec[63] == 0.0f) 1.0f else 0.0f

        // 6. Joint Threat Tells (80-83)
        val hasRatDex = (vec[34] == 1.0f || vec[38] == 1.0f || vec[40] == 1.0f)
        val hasRatPerms = (readSms || vec[3] == 1.0f)
        if (hasRatDex && isUntrusted && vec[75] == 1.0f && hasRatPerms) vec[80] = 1.0f
        if (vec[25] == 1.0f && isUntrusted && (readSms || vec[5] == 1.0f)) vec[81] = 1.0f
        if ((vec[16] == 1.0f || vec[17] == 1.0f) && (vec[36] == 1.0f || vec[42] == 1.0f) && isUntrusted) vec[82] = 1.0f
        if (vec[24] == 1.0f && isUntrusted && (vec[58] == 0.0f || vec[52] == 1.0f) && vec[39] == 1.0f) vec[83] = 1.0f

        // 7. Structural Forensics (84-91)
        val isThinDex = (totalDexSize > 0 && totalDexSize < 40000 && hasNativeLib)
        val isCorroboratedPacked = (maxAssetEntropy >= 7.80 && (vec[36] == 1.0f || isThinDex || vec[37] == 1.0f || zipTampered))

        vec[84] = if (zipTampered) 1.0f else 0.0f
        vec[85] = if (isCorroboratedPacked) 1.0f else 0.0f
        vec[86] = if (isThinDex) 1.0f else 0.0f
        vec[87] = if (hasNativeLib) 1.0f else 0.0f
        vec[88] = Math.min(htmlCardMentions.toFloat() / 20.0f, 1.0f)
        if (isCorroboratedPacked && readSms && isUntrusted) vec[89] = 1.0f
        if (zipTampered && isThinDex && (vec[16] == 1.0f || vec[17] == 1.0f || vec[36] == 1.0f)) vec[90] = 1.0f
        vec[91] = Math.min(pkgName.split(".").size.toFloat() / 8.0f, 1.0f)

        return vec
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val targetPath = if (args.isNotEmpty()) args[0] else "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk"
        val prov = if (args.size > 1) args[1] else "UNKNOWN"
        val vec = extractFromApk(targetPath, prov)
        val sb = StringBuilder()
        sb.append("[")
        for (i in vec.indices) {
            sb.append(String.format(Locale.US, "%.4f", vec[i]))
            if (i < vec.size - 1) sb.append(", ")
        }
        sb.append("]")
        println(sb.toString())
    }
}
