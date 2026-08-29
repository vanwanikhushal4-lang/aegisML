package com.aegis.guard.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.regex.Pattern
import java.util.zip.Inflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppFeatureExtractor @Inject constructor(
    private val structuralPackerDetector: StructuralPackerDetector = StructuralPackerDetector()
) {

    companion object {
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

        val KNOWN_STORES = setOf(
            "com.android.vending",
            "com.google.android.feedback",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.oppo.market",
            "com.heytap.market",
            "com.vivo.appstore",
            "com.oneplus.appstore"
        )

        val LOCAL_PACKAGE_INSTALLERS = setOf(
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.samsung.android.packageinstaller",
            "com.miui.packageinstaller",
            "com.coloros.packageinstaller",
            "com.huawei.appmarket"
        )

        val UNTRUSTED_DOWNLOADERS = setOf(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.opera.browser",
            "com.brave.browser",
            "org.telegram.messenger",
            "com.whatsapp",
            "com.google.android.apps.docs",
            "com.estrongs.android.pop",
            "com.google.android.apps.nbu.files"
        )

        val OEM_RESTORE_INSTALLERS = setOf(
            "com.sec.android.easyMover",
            "com.oneplus.backuprestore",
            "com.coloros.backuprestore",
            "com.miui.backup",
            "com.huawei.kobackup",
            "com.vivo.easyshare"
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

        val IMPERSONATION_TARGETS = listOf(
            "google service", "google play", "system update", "google framework", "android system",
            "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"
        )

        val SUSPICIOUS_PKG_TOKENS = listOf(
            "com.example", "reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealth", "stealer", "trojan"
        )
    }

    /**
     * Cryptographically inspects package signing certificate X.509 SHA-256 digest against trusted ecosystem authorities.
     * Supports Android 9+ SigningInfo (both signingCertificateHistory and apkContentsSigners) and legacy signatures.
     */
    fun isCryptographicallyTrustedPublisher(pkgInfo: PackageInfo): Boolean {
        try {
            val signatures = mutableListOf<Signature>()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.let { si ->
                    if (si.hasMultipleSigners()) {
                        si.apkContentsSigners?.let { signatures.addAll(it) }
                    } else {
                        si.signingCertificateHistory?.let { signatures.addAll(it) }
                    }
                }
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures?.let { signatures.addAll(it) }
            }

            if (signatures.isEmpty()) return false
            val md = MessageDigest.getInstance("SHA-256")

            for (sig in signatures) {
                val certBytes = sig.toByteArray()
                val sha256 = md.digest(certBytes).joinToString("") { "%02x".format(it) }.lowercase()
                if (sha256 in TRUSTED_CERT_SHA256_SET) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Certificate parse error
        }
        return false
    }

    /**
     * Extracts a 92-element float array from an installed Android package using Context.
     */
    fun extractFeatures(context: Context, pkgInfo: PackageInfo): FloatArray {
        val pm = context.packageManager
        val pkgName = pkgInfo.packageName.lowercase()

        // 7-Way Provenance Inspection
        val provenance = try {
            val appInfo = pkgInfo.applicationInfo
            val isSystem = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 else false
            val isUpdatedSystem = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 else false

            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }

            when {
                isSystem && !isUpdatedSystem -> "SYSTEM_IMAGE"
                isUpdatedSystem -> "UPDATED_SYSTEM_APP"
                installer != null && KNOWN_STORES.contains(installer) -> "VERIFIED_STORE"
                installer != null && LOCAL_PACKAGE_INSTALLERS.contains(installer) -> "CONFIRMED_LOCAL_APK"
                installer != null && UNTRUSTED_DOWNLOADERS.contains(installer) -> "DOWNLOADED_APK"
                installer != null && OEM_RESTORE_INSTALLERS.contains(installer) -> "RESTORED_OEM"
                else -> "UNKNOWN"
            }
        } catch (e: Exception) {
            "UNKNOWN"
        }

        return extractFromPackage(pkgInfo, provenance)
    }

    /**
     * Core extraction implementation from PackageInfo and Provenance string.
     */
    fun extractFromPackage(pkgInfo: PackageInfo, provenance: String = "UNKNOWN"): FloatArray {
        val vec = FloatArray(NUM_FEATURES)
        val appInfo = pkgInfo.applicationInfo

        val requestedPerms = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
        val pkgName = pkgInfo.packageName.lowercase()
        val appLabel = (appInfo?.name ?: pkgName).lowercase()
        val isSystem = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 else false

        // Provenance features (67 - 73)
        when (provenance.uppercase()) {
            "SYSTEM_IMAGE" -> vec[67] = 1.0f
            "UPDATED_SYSTEM_APP" -> vec[68] = 1.0f
            "VERIFIED_STORE" -> vec[69] = 1.0f
            "CONFIRMED_LOCAL_APK" -> vec[70] = 1.0f
            "DOWNLOADED_APK" -> vec[71] = 1.0f
            "RESTORED_OEM" -> vec[72] = 1.0f
            else -> vec[73] = 1.0f // UNKNOWN
        }

        val isKnownPub = isCryptographicallyTrustedPublisher(pkgInfo)
        vec[63] = if (isKnownPub) 1.0f else 0.0f
        vec[64] = 0.5f
        val isUntrusted = (vec[71] == 1.0f) || (vec[70] == 1.0f && !isKnownPub)

        // 1. Permissions (0 - 29)
        var dangCount = 0
        for ((perm, idx) in DANGEROUS_PERMS) {
            if (requestedPerms.contains(perm)) {
                vec[idx] = 1.0f
                dangCount++
            }
        }

        val readSms = vec[0] == 1.0f || vec[1] == 1.0f
        val sendSms = vec[2] == 1.0f
        if (readSms && sendSms) vec[23] = 1.0f

        val surveillance = vec[9] == 1.0f && (vec[7] == 1.0f || vec[8] == 1.0f) && vec[10] == 1.0f
        if (surveillance) vec[24] = 1.0f

        val overlayAccess = vec[11] == 1.0f && vec[14] == 1.0f
        if (overlayAccess) vec[25] = 1.0f

        val harvest = vec[3] == 1.0f && readSms && vec[5] == 1.0f
        if (harvest) vec[26] = 1.0f

        vec[27] = Math.min(dangCount.toFloat() / 20.0f, 1.0f)
        vec[28] = Math.min(requestedPerms.size.toFloat() / 60.0f, 1.0f)
        vec[29] = if (requestedPerms.any { it.contains("signature", ignoreCase = true) }) 1.0f else 0.0f

        // 2. DEX String / API Scanning across base & split APKs (30 - 48)
        val dexStrings = scanDexStringsFromAppInfo(appInfo)
        var hostileDexCount = 0

        fun checkDex(patterns: List<String>, idx: Int, isHostileMarker: Boolean = false) {
            val hit = patterns.any { p -> dexStrings.any { s -> s.contains(p, ignoreCase = true) } }
            if (hit) {
                vec[idx] = 1.0f
                if (isHostileMarker) {
                    hostileDexCount++
                }
            }
        }

        // SMS Manipulation (Hostile)
        checkDex(listOf("content://sms", "content://telephony/sms"), 30, isHostileMarker = true)
        checkDex(listOf("content://call_log"), 31, isHostileMarker = true)
        // Contacts Utility (Not hostile by itself)
        checkDex(listOf("content://contacts", "content://com.android.contacts"), 32, isHostileMarker = false)
        checkDex(listOf("android.telephony.SmsManager", "sendTextMessage", "SmsManager"), 33, isHostileMarker = true)
        // Shell & Process Execution (Hostile)
        checkDex(listOf("java.lang.ProcessBuilder", "ProcessBuilder"), 34, isHostileMarker = true)
        checkDex(listOf("Runtime.getRuntime().exec", "Runtime.exec"), 35, isHostileMarker = true)
        checkDex(listOf("dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"), 36, isHostileMarker = true)
        // Method.invoke & Socket (Common utility in OkHttp, Gson, React Native, etc. - Not counted in hostile summary)
        checkDex(listOf("java.lang.reflect.Method.invoke", "Method.invoke"), 37, isHostileMarker = false)
        checkDex(listOf("java.net.Socket", "Socket(", "connectSocket"), 38, isHostileMarker = false)
        checkDex(listOf("getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"), 39, isHostileMarker = true)
        checkDex(listOf("/system/bin/sh", "chmod 777", "/system/xbin/su", "which su"), 40, isHostileMarker = true)
        // Crypto & Base64 (Common utility in SharedPreferences, HTTPS - Not counted in hostile summary)
        checkDex(listOf("javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"), 41, isHostileMarker = false)
        checkDex(listOf("android.util.Base64.decode", "Base64.decode", "Base64"), 42, isHostileMarker = false)
        checkDex(listOf("/system/app/Superuser.apk", "test-keys", "busybox"), 43, isHostileMarker = true)

        val hasC2Ip = dexStrings.any { it.matches(Regex(".*\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b.*")) }
        if (hasC2Ip) {
            vec[44] = 1.0f
            hostileDexCount++
        }

        checkDex(listOf("AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo"), 45, isHostileMarker = true)
        checkDex(listOf("AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent"), 46, isHostileMarker = true)
        checkDex(listOf("SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"), 47, isHostileMarker = true)

        // COR-001: Feature 48 is strictly the normalized count of hostile DEX markers (count / 10.0)
        vec[48] = Math.min(hostileDexCount.toFloat() / 10.0f, 1.0f)

        // 3. Manifest Structure (49 - 60)
        val actCount = pkgInfo.activities?.size ?: 1
        val srvCount = pkgInfo.services?.size ?: 0
        val recCount = pkgInfo.receivers?.size ?: 0
        val totComp = actCount + srvCount + recCount

        vec[49] = Math.min(actCount.toFloat() / 20.0f, 1.0f)
        vec[50] = Math.min(srvCount.toFloat() / 10.0f, 1.0f)
        vec[51] = Math.min(recCount.toFloat() / 10.0f, 1.0f)
        vec[52] = if (requestedPerms.contains("android.permission.RECEIVE_BOOT_COMPLETED")) 1.0f else 0.0f
        vec[53] = if (requestedPerms.contains("android.permission.RECEIVE_SMS") || requestedPerms.contains("android.provider.Telephony.SMS_RECEIVED")) 1.0f else 0.0f
        vec[54] = if (requestedPerms.contains("android.permission.FOREGROUND_SERVICE")) 1.0f else 0.0f
        vec[55] = if (vec[14] == 1.0f) 1.0f else 0.0f
        vec[56] = if (vec[15] == 1.0f) 1.0f else 0.0f
        vec[57] = vec[11]
        vec[58] = 1.0f
        vec[59] = Math.min(totComp.toFloat() / 50.0f, 1.0f)

        // Feature 60: Ratio of exported components (default 0.50f when not explicitly specified)
        vec[60] = 0.50f

        // 4. Metadata (74 - 79)
        val targetSdk = appInfo?.targetSdkVersion ?: 33
        val minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) appInfo?.minSdkVersion ?: 21 else 21

        vec[74] = Math.min(targetSdk.toFloat() / 35.0f, 1.0f)
        vec[75] = if (targetSdk <= 22) 1.0f else 0.0f
        vec[76] = if (targetSdk <= 28) 1.0f else 0.0f
        vec[77] = Math.min(minSdk.toFloat() / 35.0f, 1.0f)

        val impersonates = IMPERSONATION_TARGETS.any { appLabel.contains(it) } && !isSystem && !isKnownPub
        vec[78] = if (impersonates) 1.0f else 0.0f

        val hasSuspToken = SUSPICIOUS_PKG_TOKENS.any { pkgName.contains(it) } && !isKnownPub
        vec[79] = if (hasSuspToken) 1.0f else 0.0f

        // 5. Joint High-Order Threat Tells (80 - 83)
        val hasRatDex = vec[34] == 1.0f || vec[38] == 1.0f || vec[40] == 1.0f
        val hasRatPerms = readSms || vec[3] == 1.0f
        if (hasRatDex && isUntrusted && vec[75] == 1.0f && hasRatPerms) vec[80] = 1.0f

        val hasBankPerms = readSms || vec[5] == 1.0f
        if (vec[25] == 1.0f && isUntrusted && hasBankPerms) vec[81] = 1.0f

        val hasDropPerm = vec[16] == 1.0f || vec[17] == 1.0f
        val hasDropDex = vec[36] == 1.0f || vec[42] == 1.0f
        if (hasDropPerm && hasDropDex && isUntrusted) vec[82] = 1.0f

        val hasSpyStealth = vec[58] == 0.0f || vec[52] == 1.0f
        if (vec[24] == 1.0f && isUntrusted && hasSpyStealth && vec[39] == 1.0f) vec[83] = 1.0f

        // 6. Structural Forensics (84 - 91)
        val struct = structuralPackerDetector.analyze(appInfo?.sourceDir)
        val isCorroboratedPacked = struct.maxAssetEntropy >= 7.80 && (vec[36] == 1.0f || struct.isThinDex || vec[37] == 1.0f || struct.isZipTampered)

        vec[84] = if (struct.isZipTampered) 1.0f else 0.0f
        vec[85] = if (isCorroboratedPacked) 1.0f else 0.0f
        vec[86] = if (struct.isThinDex) 1.0f else 0.0f
        vec[87] = if (struct.hasNativeLib) 1.0f else 0.0f
        vec[88] = Math.min(struct.htmlCardMentions.toFloat() / 20.0f, 1.0f)
        if (isCorroboratedPacked && readSms && isUntrusted) vec[89] = 1.0f
        if (struct.isZipTampered && struct.isThinDex && (vec[16] == 1.0f || vec[17] == 1.0f || vec[36] == 1.0f)) vec[90] = 1.0f
        vec[91] = Math.min(pkgName.split(".").size.toFloat() / 8.0f, 1.0f)

        return vec
    }

    /**
     * Direct extraction from APK file path or Split-APK directory on disk.
     */
    fun extractFromApkPath(apkPath: String, provenance: String = "UNKNOWN"): FloatArray {
        val file = File(apkPath)
        val apkFiles = mutableListOf<File>()

        if (file.isDirectory) {
            file.listFiles { f -> f.name.endsWith(".apk", ignoreCase = true) }?.let {
                apkFiles.addAll(it)
            }
        } else if (file.exists()) {
            apkFiles.add(file)
        }

        if (apkFiles.isEmpty()) return FloatArray(NUM_FEATURES)

        val baseApk = apkFiles.find { it.name.contains("base", ignoreCase = true) } ?: apkFiles.first()

        val vec = FloatArray(NUM_FEATURES)
        val manifest = parseManifestFromApk(baseApk)
        val dexStrings = mutableSetOf<String>()
        var totalDexSize = 0L
        var hasNativeLib = false
        var maxAssetEntropy = 0.0
        var htmlCardMentions = 0
        var isZipTampered = false

        val targetTokens = listOf(
            "content://sms", "content://telephony/sms", "content://call_log", "content://contacts",
            "android.telephony.SmsManager", "sendTextMessage", "SmsManager", "java.lang.ProcessBuilder",
            "ProcessBuilder", "Runtime.getRuntime().exec", "Runtime.exec", "dalvik.system.DexClassLoader",
            "DexClassLoader", "InMemoryDexClassLoader", "java.lang.reflect.Method.invoke", "Method.invoke",
            "java.net.Socket", "Socket(", "connectSocket", "getDeviceId", "getSubscriberId", "getImei",
            "/system/bin/sh", "chmod 777", "/system/xbin/su", "which su", "javax.crypto.Cipher",
            "android.util.Base64.decode", "Base64.decode", "Base64", "/system/app/Superuser.apk",
            "AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo",
            "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent",
            "SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"
        )

        for (apk in apkFiles) {
            val entries = HardenedZipReader.readApkEntries(apk)
            for (entry in entries) {
                val name = entry.name
                val data = entry.data
                if (entry.isEncryptedFlag) isZipTampered = true

                if (name.endsWith(".dex", ignoreCase = true)) {
                    totalDexSize += data.size
                    val text = String(data, StandardCharsets.ISO_8859_1)
                    for (tok in targetTokens) {
                        if (text.contains(tok)) dexStrings.add(tok)
                    }
                    if (Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b").matcher(text).find()) {
                        dexStrings.add("RAW_C2_IP")
                    }
                } else if (name.endsWith(".so", ignoreCase = true) || name.startsWith("lib/", ignoreCase = true)) {
                    hasNativeLib = true
                } else if (name.startsWith("assets/", ignoreCase = true)) {
                    if (data.size > 50000) {
                        val sampleLen = Math.min(data.size, 8192)
                        val ent = computeShannonEntropy(data, sampleLen)
                        if (ent > maxAssetEntropy) maxAssetEntropy = ent
                    }
                    if (name.endsWith(".html", ignoreCase = true) || name.endsWith(".js", ignoreCase = true)) {
                        val text = String(data, StandardCharsets.UTF_8).lowercase()
                        val count = text.split("card").size - 1
                        if (count >= 5) htmlCardMentions += count
                    }
                }
            }
        }

        // 1. Permissions (0 - 29)
        var dangCount = 0
        for (perm in manifest.permissions) {
            val idx = DANGEROUS_PERMS[perm]
            if (idx != null) {
                vec[idx] = 1.0f
                dangCount++
            }
        }

        val readSms = vec[0] == 1.0f || vec[1] == 1.0f
        val sendSms = vec[2] == 1.0f
        if (readSms && sendSms) vec[23] = 1.0f
        if (vec[9] == 1.0f && (vec[7] == 1.0f || vec[8] == 1.0f) && vec[10] == 1.0f) vec[24] = 1.0f
        if (vec[11] == 1.0f && vec[14] == 1.0f) vec[25] = 1.0f
        if (vec[3] == 1.0f && readSms && vec[5] == 1.0f) vec[26] = 1.0f

        vec[27] = Math.min(dangCount.toFloat() / 20.0f, 1.0f)
        vec[28] = Math.min(manifest.permissions.size.toFloat() / 60.0f, 1.0f)
        vec[29] = if (manifest.permissions.any { it.contains("signature", ignoreCase = true) }) 1.0f else 0.0f

        // 2. DEX Usage (30 - 48)
        var hostileDexCount = 0
        fun checkDexToken(patterns: List<String>, idx: Int, isHostile: Boolean = false) {
            if (patterns.any { dexStrings.contains(it) }) {
                vec[idx] = 1.0f
                if (isHostile) hostileDexCount++
            }
        }

        checkDexToken(listOf("content://sms", "content://telephony/sms"), 30, isHostile = true)
        checkDexToken(listOf("content://call_log"), 31, isHostile = true)
        checkDexToken(listOf("content://contacts", "com.android.contacts"), 32, isHostile = false)
        checkDexToken(listOf("android.telephony.SmsManager", "sendTextMessage", "SmsManager"), 33, isHostile = true)
        checkDexToken(listOf("java.lang.ProcessBuilder", "ProcessBuilder"), 34, isHostile = true)
        checkDexToken(listOf("Runtime.getRuntime().exec", "Runtime.exec"), 35, isHostile = true)
        checkDexToken(listOf("dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"), 36, isHostile = true)
        checkDexToken(listOf("java.lang.reflect.Method.invoke", "Method.invoke"), 37, isHostile = false)
        checkDexToken(listOf("java.net.Socket", "Socket(", "connectSocket"), 38, isHostile = false)
        checkDexToken(listOf("getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber"), 39, isHostile = true)
        checkDexToken(listOf("/system/bin/sh", "chmod 777", "/system/xbin/su", "which su"), 40, isHostile = true)
        checkDexToken(listOf("javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"), 41, isHostile = false)
        checkDexToken(listOf("android.util.Base64.decode", "Base64.decode", "Base64"), 42, isHostile = false)
        checkDexToken(listOf("/system/app/Superuser.apk", "test-keys", "busybox"), 43, isHostile = true)
        checkDexToken(listOf("RAW_C2_IP"), 44, isHostile = true)
        checkDexToken(listOf("AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo"), 45, isHostile = true)
        checkDexToken(listOf("AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent"), 46, isHostile = true)
        checkDexToken(listOf("SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"), 47, isHostile = true)

        vec[48] = Math.min(hostileDexCount.toFloat() / 10.0f, 1.0f)

        // 3. Manifest Components (49 - 60)
        val actCount = Math.max(manifest.activities.size, 1)
        val srvCount = manifest.services.size
        val recCount = manifest.receivers.size
        val totComp = actCount + srvCount + recCount

        vec[49] = Math.min(actCount.toFloat() / 20.0f, 1.0f)
        vec[50] = Math.min(srvCount.toFloat() / 10.0f, 1.0f)
        vec[51] = Math.min(recCount.toFloat() / 10.0f, 1.0f)
        vec[52] = if (manifest.permissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")) 1.0f else 0.0f
        vec[53] = if (manifest.permissions.contains("android.permission.RECEIVE_SMS") || manifest.permissions.contains("android.provider.Telephony.SMS_RECEIVED")) 1.0f else 0.0f
        vec[54] = if (manifest.permissions.contains("android.permission.FOREGROUND_SERVICE")) 1.0f else 0.0f
        vec[55] = vec[14]
        vec[56] = vec[15]
        vec[57] = vec[11]
        vec[58] = 1.0f
        vec[59] = Math.min(totComp.toFloat() / 50.0f, 1.0f)
        vec[60] = 0.50f

        // 4. Certificates (61 - 66)
        var isDebug = false
        var isKnownPub = false
        var certCount = 0

        for (apk in apkFiles) {
            val entries = HardenedZipReader.readApkEntries(apk)
            for (item in entries) {
                if (item.name.startsWith("META-INF/") && (item.name.endsWith(".RSA") || item.name.endsWith(".DSA") || item.name.endsWith(".EC") || item.name.endsWith(".der"))) {
                    try {
                        val cf = CertificateFactory.getInstance("X.509")
                        val certList = cf.generateCertificates(ByteArrayInputStream(item.data))
                        certCount += certList.size
                        for (c in certList) {
                            val xc = c as? X509Certificate ?: continue
                            val subj = xc.subjectDN.name.lowercase()
                            val issuer = xc.issuerDN.name.lowercase()
                            if (subj.contains("debug") || issuer.contains("debug") || subj.contains("test-keys") || subj.contains("testkey")) {
                                isDebug = true
                            } else if (!isDebug) {
                                val md = MessageDigest.getInstance("SHA-256")
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

        // 5. Provenance (67 - 73)
        when (provenance.uppercase()) {
            "SYSTEM_IMAGE" -> vec[67] = 1.0f
            "UPDATED_SYSTEM_APP" -> vec[68] = 1.0f
            "VERIFIED_STORE" -> vec[69] = 1.0f
            "CONFIRMED_LOCAL_APK" -> vec[70] = 1.0f
            "DOWNLOADED_APK" -> vec[71] = 1.0f
            "RESTORED_OEM" -> vec[72] = 1.0f
            else -> vec[73] = 1.0f // UNKNOWN
        }

        val isUntrusted = (vec[71] == 1.0f) || (vec[70] == 1.0f && !isKnownPub)

        // 6. Metadata (74 - 79)
        val targetSdk = manifest.targetSdkVersion
        val minSdk = manifest.minSdkVersion

        vec[74] = Math.min(targetSdk.toFloat() / 35.0f, 1.0f)
        vec[75] = if (targetSdk <= 22) 1.0f else 0.0f
        vec[76] = if (targetSdk <= 28) 1.0f else 0.0f
        vec[77] = Math.min(minSdk.toFloat() / 35.0f, 1.0f)

        val isSystemApp = vec[67] == 1.0f || vec[68] == 1.0f
        val impersonates = IMPERSONATION_TARGETS.any { manifest.packageName.contains(it) } && !isSystemApp && !isKnownPub
        vec[78] = if (impersonates) 1.0f else 0.0f

        val hasSuspToken = SUSPICIOUS_PKG_TOKENS.any { manifest.packageName.contains(it) } && !isKnownPub
        vec[79] = if (hasSuspToken) 1.0f else 0.0f

        // 7. Joint Threat Combinations (80 - 83)
        val hasRatDex = vec[34] == 1.0f || vec[38] == 1.0f || vec[40] == 1.0f
        val hasRatPerms = readSms || vec[3] == 1.0f
        if (hasRatDex && isUntrusted && vec[75] == 1.0f && hasRatPerms) vec[80] = 1.0f

        val hasBankPerms = readSms || vec[5] == 1.0f
        if (vec[25] == 1.0f && isUntrusted && hasBankPerms) vec[81] = 1.0f

        val hasDropPerm = vec[16] == 1.0f || vec[17] == 1.0f
        val hasDropDex = vec[36] == 1.0f || vec[42] == 1.0f
        if (hasDropPerm && hasDropDex && isUntrusted) vec[82] = 1.0f

        val hasSpyStealth = vec[58] == 0.0f || vec[52] == 1.0f
        if (vec[24] == 1.0f && isUntrusted && hasSpyStealth && vec[39] == 1.0f) vec[83] = 1.0f

        // 8. Structural Forensics (84 - 91)
        val isThinDex = totalDexSize in 1..40000L && hasNativeLib
        val isCorroboratedPacked = maxAssetEntropy >= 7.80 && (vec[36] == 1.0f || isThinDex || vec[37] == 1.0f || isZipTampered)

        vec[84] = if (isZipTampered) 1.0f else 0.0f
        vec[85] = if (isCorroboratedPacked) 1.0f else 0.0f
        vec[86] = if (isThinDex) 1.0f else 0.0f
        vec[87] = if (hasNativeLib) 1.0f else 0.0f
        vec[88] = Math.min(htmlCardMentions.toFloat() / 20.0f, 1.0f)
        if (isCorroboratedPacked && readSms && isUntrusted) vec[89] = 1.0f
        if (isZipTampered && isThinDex && (vec[16] == 1.0f || vec[17] == 1.0f || vec[36] == 1.0f)) vec[90] = 1.0f
        vec[91] = Math.min(manifest.packageName.split(".").size.toFloat() / 8.0f, 1.0f)

        return vec
    }

    private fun scanDexStringsFromAppInfo(appInfo: ApplicationInfo?): Set<String> {
        if (appInfo == null) return emptySet()
        val allStrings = mutableSetOf<String>()

        val paths = mutableListOf<String>()
        appInfo.sourceDir?.let { paths.add(it) }
        appInfo.splitSourceDirs?.let { paths.addAll(it) }

        for (path in paths) {
            allStrings.addAll(scanDexStrings(path))
        }
        return allStrings
    }

    private fun scanDexStrings(apkPath: String?): Set<String> {
        if (apkPath == null) return emptySet()
        val file = File(apkPath)
        if (!file.exists()) return emptySet()

        val extracted = mutableSetOf<String>()
        val targetTokens = listOf(
            "content://sms", "content://telephony/sms", "content://call_log", "content://contacts",
            "android.telephony.SmsManager", "sendTextMessage", "SmsManager", "java.lang.ProcessBuilder",
            "ProcessBuilder", "Runtime.getRuntime().exec", "Runtime.exec", "dalvik.system.DexClassLoader",
            "DexClassLoader", "InMemoryDexClassLoader", "java.lang.reflect.Method.invoke", "Method.invoke",
            "java.net.Socket", "Socket(", "connectSocket", "getDeviceId", "getSubscriberId", "getImei",
            "/system/bin/sh", "chmod 777", "/system/xbin/su", "which su", "javax.crypto.Cipher",
            "android.util.Base64.decode", "Base64.decode", "Base64", "/system/app/Superuser.apk",
            "AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo",
            "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent",
            "SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"
        )

        val entries = HardenedZipReader.readApkEntries(file)
        for (entry in entries) {
            if (entry.name.endsWith(".dex", ignoreCase = true)) {
                val text = String(entry.data, StandardCharsets.ISO_8859_1)
                for (token in targetTokens) {
                    if (text.contains(token)) {
                        extracted.add(token)
                    }
                }
                if (Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b").matcher(text).find()) {
                    extracted.add("RAW_C2_IP")
                }
            }
        }
        return extracted
    }

    private data class ParsedManifest(
        var packageName: String = "",
        var targetSdkVersion: Int = 33,
        var minSdkVersion: Int = 21,
        val permissions: MutableList<String> = mutableListOf(),
        val activities: MutableList<String> = mutableListOf(),
        val services: MutableList<String> = mutableListOf(),
        val receivers: MutableList<String> = mutableListOf()
    )

    private fun parseManifestFromApk(apkFile: File): ParsedManifest {
        val manifest = ParsedManifest()
        val entries = HardenedZipReader.readApkEntries(apkFile)
        val manifestEntry = entries.find { it.name == "AndroidManifest.xml" } ?: return manifest
        val axml = manifestEntry.data

        try {
            val buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN)
            if (buf.remaining() < 8) return manifest
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
                    buf.getInt()
                    val flags = buf.getInt()
                    val stringsStart = buf.getInt()
                    buf.getInt()
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
                    buf.getInt(); buf.getInt(); buf.getInt()
                    val nameIdx = buf.getInt()
                    val tagName = if (nameIdx in stringPool.indices) stringPool[nameIdx] else ""
                    buf.getShort(); buf.getShort()
                    val attrCount = buf.getShort().toInt() and 0xFFFF
                    buf.getShort(); buf.getShort(); buf.getShort()

                    val attrs = mutableMapOf<String, Any>()
                    for (a in 0 until attrCount) {
                        buf.getInt()
                        val aNameIdx = buf.getInt()
                        val aRawVal = buf.getInt()
                        val aType = buf.getInt()
                        val aData = buf.getInt()
                        val aName = if (aNameIdx in stringPool.indices) stringPool[aNameIdx] else ""
                        val aStrVal = if (aRawVal in stringPool.indices) stringPool[aRawVal] else ""

                        if (aType == 0x03) attrs[aName] = aStrVal
                        else if (aType == 0x10 || aType == 0x11 || aType == 0x12) attrs[aName] = aData
                        else attrs[aName] = if (aStrVal.isNotEmpty()) aStrVal else aData
                    }

                    when (tagName) {
                        "manifest" -> {
                            val pkg = attrs["package"]
                            if (pkg is String) manifest.packageName = pkg.lowercase()
                        }
                        "uses-sdk" -> {
                            val tSdk = attrs["targetSdkVersion"]
                            if (tSdk is Int) manifest.targetSdkVersion = tSdk
                            val mSdk = attrs["minSdkVersion"]
                            if (mSdk is Int) manifest.minSdkVersion = mSdk
                        }
                        "uses-permission", "permission" -> {
                            val pName = attrs["name"]
                            if (pName is String) manifest.permissions.add(pName)
                        }
                        "activity", "activity-alias" -> {
                            val actName = attrs["name"]
                            if (actName is String) manifest.activities.add(actName)
                        }
                        "service" -> {
                            val srvName = attrs["name"]
                            if (srvName is String) manifest.services.add(srvName)
                        }
                        "receiver" -> {
                            val recName = attrs["name"]
                            if (recName is String) manifest.receivers.add(recName)
                        }
                    }
                }
                buf.position(chunkPos + chunkSize)
            }
        } catch (ignored: Exception) {}
        return manifest
    }

    private fun computeShannonEntropy(bytes: ByteArray, length: Int): Double {
        if (length == 0) return 0.0
        val freq = IntArray(256)
        for (i in 0 until length) {
            freq[bytes[i].toInt() and 0xFF]++
        }
        var entropy = 0.0
        val lenD = length.toDouble()
        for (f in freq) {
            if (f > 0) {
                val p = f.toDouble() / lenD
                entropy -= p * (Math.log(p) / Math.log(2.0))
            }
        }
        return entropy
    }
}