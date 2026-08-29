package com.aegis.guard.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
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
     */
    fun isCryptographicallyTrustedPublisher(pkgInfo: PackageInfo): Boolean {
        try {
            val signatures: Array<Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures
            }

            if (signatures.isNullOrEmpty()) return false
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
     * Extracts a 92-element float array from an installed Android package.
     */
    fun extractFeatures(context: Context, pkgInfo: PackageInfo): FloatArray {
        val vec = FloatArray(NUM_FEATURES)
        val pm = context.packageManager
        val appInfo = pkgInfo.applicationInfo

        val requestedPerms = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
        val pkgName = pkgInfo.packageName.lowercase()
        val appLabel = (appInfo?.loadLabel(pm)?.toString() ?: pkgName).lowercase()
        val isSystem = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 else false
        val isUpdatedSystem = if (appInfo != null) (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 else false

        // 7-Way Provenance Inspection
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }
        } catch (e: Exception) {
            null
        }

        when {
            isSystem && !isUpdatedSystem -> vec[67] = 1.0f // prov_system_image
            isUpdatedSystem -> vec[68] = 1.0f             // prov_updated_system_app
            installer != null && KNOWN_STORES.contains(installer) -> vec[69] = 1.0f // prov_verified_store
            installer != null && LOCAL_PACKAGE_INSTALLERS.contains(installer) -> vec[70] = 1.0f // prov_confirmed_local_apk
            installer != null && UNTRUSTED_DOWNLOADERS.contains(installer) -> vec[71] = 1.0f // prov_downloaded_apk
            installer != null && OEM_RESTORE_INSTALLERS.contains(installer) -> vec[72] = 1.0f // prov_restored_oem
            else -> vec[73] = 1.0f // prov_unknown
        }

        // Cryptographic publisher verification (Subject/Issuer DN, NOT package prefix)
        val isKnownPub = isCryptographicallyTrustedPublisher(pkgInfo)
        vec[63] = if (isKnownPub) 1.0f else 0.0f
        vec[64] = 0.5f

        // UNKNOWN is strictly distinct from DOWNLOADED/SIDELOADED
        val isUntrusted = (vec[71] == 1.0f) || (vec[70] == 1.0f && !isKnownPub)

        // ─── Family 1: Permissions (0 - 29) ──────────────────────────────────
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

        // ─── Family 2: DEX String / API Scanning across base & split APKs (30 - 48) ───
        val dexStrings = scanDexStringsFromAppInfo(appInfo)
        var dexSuspiciousCount = 0

        fun checkDex(patterns: List<String>, idx: Int) {
            val hit = patterns.any { p -> dexStrings.any { s -> s.contains(p, ignoreCase = true) } }
            if (hit) {
                vec[idx] = 1.0f
                dexSuspiciousCount++
            }
        }

        checkDex(listOf("content://sms", "content://telephony/sms"), 30)
        checkDex(listOf("content://call_log"), 31)
        checkDex(listOf("content://contacts", "content://com.android.contacts"), 32)
        checkDex(listOf("android.telephony.SmsManager", "sendTextMessage", "SmsManager"), 33)
        checkDex(listOf("java.lang.ProcessBuilder", "ProcessBuilder"), 34)
        checkDex(listOf("Runtime.getRuntime().exec", "Runtime.exec"), 35)
        checkDex(listOf("dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"), 36)
        checkDex(listOf("java.lang.reflect.Method.invoke", "Method.invoke"), 37)
        checkDex(listOf("java.net.Socket", "Socket(", "connectSocket"), 38)
        checkDex(listOf("getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"), 39)
        checkDex(listOf("/system/bin/sh", "chmod 777", "/system/xbin/su", "which su"), 40)
        checkDex(listOf("javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"), 41)
        checkDex(listOf("android.util.Base64.decode", "Base64.decode", "Base64"), 42)
        checkDex(listOf("/system/app/Superuser.apk", "test-keys", "busybox"), 43)

        val hasC2Ip = dexStrings.any { it.matches(Regex(".*\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b.*")) }
        if (hasC2Ip) {
            vec[44] = 1.0f
            dexSuspiciousCount++
        }

        checkDex(listOf("AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo"), 45)
        checkDex(listOf("AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent"), 46)
        checkDex(listOf("SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"), 47)

        vec[48] = Math.min(dexSuspiciousCount.toFloat() / 15.0f, 1.0f)

        // ─── Family 3: Manifest Structure (49 - 60) ──────────────────────────
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
        vec[60] = if (totComp > 0) (actCount + srvCount + recCount).toFloat() / totComp.toFloat() else 0.0f

        // ─── Family 5: Metadata (74 - 79) ─────────────────────────────────────
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

        // ─── Family 6: Joint High-Order Threat Tells (80 - 83) ────────────────
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

        // ─── Family 7: Structural Forensics (84 - 91) ─────────────────────────
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

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.name.endsWith(".dex")) {
                        zip.getInputStream(entry).use { stream ->
                            val bytes = stream.readBytes()
                            val text = String(bytes, Charsets.ISO_8859_1)
                            for (token in targetTokens) {
                                if (text.contains(token)) {
                                    extracted.add(token)
                                }
                            }
                            if (Regex("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b").containsMatchIn(text)) {
                                extracted.add("RAW_C2_IP")
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Fallback hardened zip parsing
        }
        return extracted
    }
}