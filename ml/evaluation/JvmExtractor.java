import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class JvmExtractor {
    public static final int NUM_FEATURES = 92;

    public static final Map<String, Integer> DANGEROUS_PERMS = new HashMap<>();
    static {
        DANGEROUS_PERMS.put("android.permission.READ_SMS", 0);
        DANGEROUS_PERMS.put("android.permission.RECEIVE_SMS", 1);
        DANGEROUS_PERMS.put("android.permission.SEND_SMS", 2);
        DANGEROUS_PERMS.put("android.permission.READ_CALL_LOG", 3);
        DANGEROUS_PERMS.put("android.permission.WRITE_CALL_LOG", 4);
        DANGEROUS_PERMS.put("android.permission.READ_CONTACTS", 5);
        DANGEROUS_PERMS.put("android.permission.WRITE_CONTACTS", 6);
        DANGEROUS_PERMS.put("android.permission.ACCESS_FINE_LOCATION", 7);
        DANGEROUS_PERMS.put("android.permission.ACCESS_COARSE_LOCATION", 8);
        DANGEROUS_PERMS.put("android.permission.RECORD_AUDIO", 9);
        DANGEROUS_PERMS.put("android.permission.CAMERA", 10);
        DANGEROUS_PERMS.put("android.permission.SYSTEM_ALERT_WINDOW", 11);
        DANGEROUS_PERMS.put("android.permission.READ_PHONE_STATE", 12);
        DANGEROUS_PERMS.put("android.permission.PROCESS_OUTGOING_CALLS", 13);
        DANGEROUS_PERMS.put("android.permission.BIND_ACCESSIBILITY_SERVICE", 14);
        DANGEROUS_PERMS.put("android.permission.BIND_DEVICE_ADMIN", 15);
        DANGEROUS_PERMS.put("android.permission.REQUEST_INSTALL_PACKAGES", 16);
        DANGEROUS_PERMS.put("android.permission.INSTALL_PACKAGES", 17);
        DANGEROUS_PERMS.put("android.permission.QUERY_ALL_PACKAGES", 18);
        DANGEROUS_PERMS.put("android.permission.ACCESS_BACKGROUND_LOCATION", 19);
        DANGEROUS_PERMS.put("android.permission.USE_BIOMETRIC", 20);
        DANGEROUS_PERMS.put("android.permission.WRITE_SETTINGS", 21);
        DANGEROUS_PERMS.put("android.permission.GET_ACCOUNTS", 22);
    }

    public static final Set<String> TRUSTED_PUBLISHERS = new HashSet<>(Arrays.asList(
        "com.google.android", "com.google.android.apps", "com.whatsapp",
        "com.phonepe.app", "net.one97.paytm", "com.sbi.lotusintouch",
        "com.hdfcbank.payzapp", "com.msf.kbank.mobile", "com.icicibank.mobile",
        "com.ubercab", "com.spotify.music", "org.mozilla.firefox", "com.microsoft.teams",
        "com.sec.android", "com.samsung.android", "com.oneplus", "com.oppo", "com.coloros",
        "com.realme", "com.miui", "com.xiaomi"
    ));

    public static class ZipItem {
        public String name;
        public byte[] data;
        public boolean isEncryptedFlag;
    }

    public static class ManifestData {
        public String packageName = "";
        public int targetSdkVersion = 33;
        public int minSdkVersion = 21;
        public Set<String> permissions = new HashSet<>();
        public List<String> activities = new ArrayList<>();
        public List<String> services = new ArrayList<>();
        public List<String> receivers = new ArrayList<>();
        public List<String> providers = new ArrayList<>();
        public boolean hasBootReceiver = false;
        public boolean hasSmsReceiver = false;
        public boolean hasForegroundService = false;
        public boolean hasAccessibilityService = false;
        public boolean hasDeviceAdmin = false;
        public boolean hasSystemAlertWindow = false;
        public boolean hasLauncherActivity = false;
        public String appLabel = "";
    }

    private static double computeShannonEntropy(byte[] data, int length) {
        if (length <= 0) return 0.0;
        int[] freq = new int[256];
        for (int i = 0; i < length; i++) {
            freq[data[i] & 0xFF]++;
        }
        double entropy = 0.0;
        double lenD = (double) length;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / lenD;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private static List<ZipItem> readApkEntries(File file) {
        List<ZipItem> items = new ArrayList<>();
        try (ZipFile zip = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                ZipItem item = new ZipItem();
                item.name = entry.getName();
                try (InputStream is = zip.getInputStream(entry)) {
                    item.data = is.readAllBytes();
                } catch (Exception e) {
                    item.data = new byte[0];
                }
                item.isEncryptedFlag = false;
                items.add(item);
            }
            return items;
        } catch (Exception ex) {
            // Use fallback hardened local header reader for corrupt/anti-analysis ZIP
            return readApkHardened(file);
        }
    }

    private static List<ZipItem> readApkHardened(File file) {
        List<ZipItem> entries = new ArrayList<>();
        try {
            byte[] apkBytes = java.nio.file.Files.readAllBytes(file.toPath());
            ByteBuffer buf = ByteBuffer.wrap(apkBytes).order(ByteOrder.LITTLE_ENDIAN);
            int pos = 0;
            int len = apkBytes.length;

            while (pos < len - 30) {
                if (buf.getInt(pos) == 0x04034b50) {
                    int flags = buf.getShort(pos + 6) & 0xFFFF;
                    int method = buf.getShort(pos + 8) & 0xFFFF;
                    int cSize = buf.getInt(pos + 18);
                    int uSize = buf.getInt(pos + 22);
                    int nameLen = buf.getShort(pos + 26) & 0xFFFF;
                    int extraLen = buf.getShort(pos + 28) & 0xFFFF;

                    int nameStart = pos + 30;
                    if (nameStart + nameLen <= len) {
                        byte[] nameBytes = new byte[nameLen];
                        System.arraycopy(apkBytes, nameStart, nameBytes, 0, nameLen);
                        String name = new String(nameBytes, StandardCharsets.UTF_8);

                        int dataStart = nameStart + nameLen + extraLen;
                        byte[] data = new byte[0];

                        if (cSize > 0 && dataStart + cSize <= len) {
                            byte[] compData = new byte[cSize];
                            System.arraycopy(apkBytes, dataStart, compData, 0, cSize);

                            if (method == 0) {
                                data = compData;
                            } else if (method == 8) {
                                try {
                                    Inflater inflater = new Inflater(true);
                                    inflater.setInput(compData);
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream(uSize > 0 ? uSize : cSize * 2);
                                    byte[] tmp = new byte[4096];
                                    while (!inflater.finished()) {
                                        int count = inflater.inflate(tmp);
                                        if (count == 0) break;
                                        baos.write(tmp, 0, count);
                                    }
                                    inflater.end();
                                    data = baos.toByteArray();
                                } catch (Exception ignored) {}
                            }
                        }

                        ZipItem e = new ZipItem();
                        e.name = name;
                        e.data = data;
                        e.isEncryptedFlag = (flags & 0x0001) != 0;
                        entries.add(e);
                    }
                    pos += 30 + nameLen + extraLen + (cSize > 0 ? cSize : 0);
                } else {
                    pos++;
                }
            }
        } catch (Exception ignored) {}
        return entries;
    }

    public static ManifestData parseAxml(byte[] axml) {
        ManifestData data = new ManifestData();
        try {
            ByteBuffer buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN);
            if (buf.remaining() < 8) return data;

            int magic = buf.getInt();
            int fileSize = buf.getInt();

            List<String> stringPool = new ArrayList<>();

            while (buf.hasRemaining()) {
                int chunkPos = buf.position();
                if (buf.remaining() < 8) break;
                int chunkType = buf.getInt();
                int chunkSize = buf.getInt();
                if (chunkSize <= 0 || chunkPos + chunkSize > axml.length) break;

                if (chunkType == 0x001C0001) { // String Pool
                    int stringCount = buf.getInt();
                    int styleCount = buf.getInt();
                    int flags = buf.getInt();
                    int stringsStart = buf.getInt();
                    int stylesStart = buf.getInt();

                    int[] offsets = new int[stringCount];
                    for (int i = 0; i < stringCount; i++) {
                        offsets[i] = buf.getInt();
                    }

                    int poolStart = chunkPos + stringsStart;
                    boolean isUtf8 = (flags & (1 << 8)) != 0;

                    for (int i = 0; i < stringCount; i++) {
                        int pos = poolStart + offsets[i];
                        if (pos < axml.length) {
                            buf.position(pos);
                            if (isUtf8) {
                                int len = buf.get() & 0xFF;
                                int byteLen = buf.get() & 0xFF;
                                byte[] strBytes = new byte[byteLen];
                                buf.get(strBytes);
                                stringPool.add(new String(strBytes, StandardCharsets.UTF_8));
                            } else {
                                int len = buf.getShort() & 0xFFFF;
                                byte[] strBytes = new byte[len * 2];
                                buf.get(strBytes);
                                stringPool.add(new String(strBytes, StandardCharsets.UTF_16LE));
                            }
                        } else {
                            stringPool.add("");
                        }
                    }
                } else if (chunkType == 0x00100102) { // START_TAG
                    int lineNumber = buf.getInt();
                    int comment = buf.getInt();
                    int nsUri = buf.getInt();
                    int nameIdx = buf.getInt();
                    String tagName = (nameIdx >= 0 && nameIdx < stringPool.size()) ? stringPool.get(nameIdx) : "";

                    int attrStart = buf.getShort() & 0xFFFF;
                    int attrSize = buf.getShort() & 0xFFFF;
                    int attrCount = buf.getShort() & 0xFFFF;
                    int idIndex = buf.getShort() & 0xFFFF;
                    int classIndex = buf.getShort() & 0xFFFF;
                    int styleIndex = buf.getShort() & 0xFFFF;

                    Map<String, Object> attrs = new HashMap<>();
                    for (int a = 0; a < attrCount; a++) {
                        int aNs = buf.getInt();
                        int aNameIdx = buf.getInt();
                        int aRawVal = buf.getInt();
                        int aType = buf.getInt();
                        int aData = buf.getInt();

                        String aName = (aNameIdx >= 0 && aNameIdx < stringPool.size()) ? stringPool.get(aNameIdx) : "";
                        String aStrVal = (aRawVal >= 0 && aRawVal < stringPool.size()) ? stringPool.get(aRawVal) : "";

                        if (aType == 0x03) { // string
                            attrs.put(aName, aStrVal);
                        } else if (aType == 0x10 || aType == 0x11 || aType == 0x12) { // int / hex / bool
                            attrs.put(aName, aData);
                        } else {
                            attrs.put(aName, aStrVal.isEmpty() ? aData : aStrVal);
                        }
                    }

                    if ("manifest".equals(tagName)) {
                        Object pkg = attrs.get("package");
                        if (pkg instanceof String) data.packageName = ((String) pkg).toLowerCase();
                    } else if ("uses-sdk".equals(tagName)) {
                        Object tSdk = attrs.get("targetSdkVersion");
                        if (tSdk instanceof Integer) data.targetSdkVersion = (Integer) tSdk;
                        Object mSdk = attrs.get("minSdkVersion");
                        if (mSdk instanceof Integer) data.minSdkVersion = (Integer) mSdk;
                    } else if ("uses-permission".equals(tagName) || "permission".equals(tagName)) {
                        Object pName = attrs.get("name");
                        if (pName instanceof String) data.permissions.add((String) pName);
                    } else if ("activity".equals(tagName) || "activity-alias".equals(tagName)) {
                        Object actName = attrs.get("name");
                        if (actName instanceof String) data.activities.add((String) actName);
                    } else if ("service".equals(tagName)) {
                        Object srvName = attrs.get("name");
                        if (srvName instanceof String) data.services.add((String) srvName);
                    } else if ("receiver".equals(tagName)) {
                        Object recName = attrs.get("name");
                        if (recName instanceof String) data.receivers.add((String) recName);
                    } else if ("action".equals(tagName)) {
                        Object act = attrs.get("name");
                        if (act instanceof String) {
                            String s = (String) act;
                            if ("android.intent.action.BOOT_COMPLETED".equals(s)) data.hasBootReceiver = true;
                            if ("android.provider.Telephony.SMS_RECEIVED".equals(s) || "android.provider.Telephony.SMS_DELIVER".equals(s)) data.hasSmsReceiver = true;
                            if ("android.intent.action.MAIN".equals(s)) data.hasLauncherActivity = true;
                        }
                    } else if ("application".equals(tagName)) {
                        Object label = attrs.get("label");
                        if (label instanceof String) data.appLabel = (String) label;
                    }
                }

                buf.position(chunkPos + chunkSize);
            }
        } catch (Exception e) {
            // fallback
        }
        return data;
    }

    public static float[] extractFromApk(String apkPath, String provenance) throws Exception {
        float[] vec = new float[NUM_FEATURES];
        File file = new File(apkPath);
        if (!file.exists()) {
            throw new IllegalArgumentException("APK file not found: " + apkPath);
        }

        Set<String> dexStrings = new HashSet<>();
        ManifestData manifest = new ManifestData();
        long totalDexSize = 0L;
        boolean hasNativeLib = false;
        double maxAssetEntropy = 0.0;
        int htmlCardMentions = 0;
        boolean zipTampered = false;
        String arscContent = "";

        List<ZipItem> entries = readApkEntries(file);

        for (ZipItem item : entries) {
            String name = item.name;
            byte[] bytes = item.data;
            if (item.isEncryptedFlag) zipTampered = true;

            if (name.endsWith(".dex")) {
                totalDexSize += bytes.length;
                String content = new String(bytes, StandardCharsets.ISO_8859_1);
                String[] targets = {
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
                };
                for (String t : targets) {
                    if (content.contains(t)) {
                        dexStrings.add(t);
                    }
                }
                if (Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}\\b").matcher(content).find()) {
                    dexStrings.add("RAW_C2_IP");
                }
            } else if (name.equals("AndroidManifest.xml")) {
                manifest = parseAxml(bytes);
            } else if (name.equals("resources.arsc")) {
                arscContent = new String(bytes, StandardCharsets.ISO_8859_1).toLowerCase();
            } else if (name.endsWith(".so") || name.startsWith("lib/")) {
                hasNativeLib = true;
            } else if (name.startsWith("assets/")) {
                if (bytes.length > 50000) {
                    int sampleLen = Math.min(bytes.length, 8192);
                    double ent = computeShannonEntropy(bytes, sampleLen);
                    if (ent > maxAssetEntropy) maxAssetEntropy = ent;
                }
                if (name.endsWith(".html") || name.endsWith(".js")) {
                    String text = new String(bytes, StandardCharsets.UTF_8).toLowerCase();
                    int cardCount = text.split("card", -1).length - 1;
                    if (cardCount >= 5) htmlCardMentions += cardCount;
                }
            }
        }

        // 1. Permissions (0-29)
        int dangCount = 0;
        for (String perm : manifest.permissions) {
            if (DANGEROUS_PERMS.containsKey(perm)) {
                vec[DANGEROUS_PERMS.get(perm)] = 1.0f;
                dangCount++;
            }
        }

        boolean readSms = (vec[0] == 1.0f || vec[1] == 1.0f);
        boolean sendSms = (vec[2] == 1.0f);
        if (readSms && sendSms) vec[23] = 1.0f;
        if (vec[9] == 1.0f && (vec[7] == 1.0f || vec[8] == 1.0f) && vec[10] == 1.0f) vec[24] = 1.0f;
        if (vec[11] == 1.0f && vec[14] == 1.0f) vec[25] = 1.0f;
        if (vec[3] == 1.0f && readSms && vec[5] == 1.0f) vec[26] = 1.0f;

        vec[27] = Math.min((float) dangCount / 20.0f, 1.0f);
        vec[28] = Math.min((float) manifest.permissions.size() / 60.0f, 1.0f);
        boolean hasSignature = manifest.permissions.stream().anyMatch(p -> p.toLowerCase().contains("signature"));
        vec[29] = hasSignature ? 1.0f : 0.0f;

        // 2. DEX Usage (30-48)
        int dexSuspCount = 0;
        if (dexStrings.contains("content://sms") || dexStrings.contains("content://telephony/sms")) { vec[30] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("content://call_log")) { vec[31] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("content://contacts") || dexStrings.contains("com.android.contacts")) { vec[32] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("android.telephony.SmsManager") || dexStrings.contains("sendTextMessage") || dexStrings.contains("SmsManager")) { vec[33] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("java.lang.ProcessBuilder") || dexStrings.contains("ProcessBuilder")) { vec[34] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("Runtime.getRuntime().exec") || dexStrings.contains("Runtime.exec")) { vec[35] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("dalvik.system.DexClassLoader") || dexStrings.contains("DexClassLoader") || dexStrings.contains("InMemoryDexClassLoader")) { vec[36] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("java.lang.reflect.Method.invoke") || dexStrings.contains("Method.invoke")) { vec[37] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("java.net.Socket") || dexStrings.contains("Socket(") || dexStrings.contains("connectSocket")) { vec[38] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("getDeviceId") || dexStrings.contains("getSubscriberId") || dexStrings.contains("getImei") || dexStrings.contains("getSimSerialNumber")) { vec[39] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("/system/bin/sh") || dexStrings.contains("chmod 777") || dexStrings.contains("/system/xbin/su") || dexStrings.contains("which su")) { vec[40] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("javax.crypto.Cipher") || dexStrings.contains("DESede") || dexStrings.contains("AES/CBC/PKCS5Padding")) { vec[41] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("android.util.Base64.decode") || dexStrings.contains("Base64.decode") || dexStrings.contains("Base64")) { vec[42] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("/system/app/Superuser.apk") || dexStrings.contains("test-keys") || dexStrings.contains("busybox")) { vec[43] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("RAW_C2_IP")) { vec[44] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("AccessibilityNodeInfo.performAction") || dexStrings.contains("ACTION_CLICK") || dexStrings.contains("dispatchGesture") || dexStrings.contains("AccessibilityNodeInfo")) { vec[45] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED") || dexStrings.contains("OnKeyListener") || dexStrings.contains("keylogger") || dexStrings.contains("KeyEvent")) { vec[46] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("SurfaceTexture(0)") || dexStrings.contains("hidden_camera_capture") || dexStrings.contains("camera_surface_null") || dexStrings.contains("api.telegram.org")) { vec[47] = 1.0f; dexSuspCount++; }

        vec[48] = Math.min((float) dexSuspCount / 15.0f, 1.0f);

        // 3. Manifest Structure (49-60)
        int actCount = Math.max(manifest.activities.size(), 1);
        int srvCount = manifest.services.size();
        int recCount = manifest.receivers.size();
        int totComp = actCount + srvCount + recCount;
        vec[49] = Math.min((float) actCount / 20.0f, 1.0f);
        vec[50] = Math.min((float) srvCount / 10.0f, 1.0f);
        vec[51] = Math.min((float) recCount / 10.0f, 1.0f);
        vec[52] = (manifest.hasBootReceiver || manifest.permissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")) ? 1.0f : 0.0f;
        vec[53] = (manifest.hasSmsReceiver || manifest.permissions.contains("android.permission.RECEIVE_SMS")) ? 1.0f : 0.0f;
        vec[54] = (manifest.hasForegroundService || manifest.permissions.contains("android.permission.FOREGROUND_SERVICE")) ? 1.0f : 0.0f;
        vec[55] = vec[14];
        vec[56] = vec[15];
        vec[57] = vec[11];
        vec[58] = (manifest.hasLauncherActivity || actCount > 0) ? 1.0f : 0.0f;
        vec[59] = Math.min((float) totComp / 50.0f, 1.0f);
        vec[60] = 0.50f;

        // 4. Certificates (61-66)
        String pkgName = manifest.packageName;
        boolean isKnownPub = false;
        for (String pub : TRUSTED_PUBLISHERS) {
            if (pkgName.startsWith(pub)) {
                isKnownPub = true;
                break;
            }
        }
        vec[63] = isKnownPub ? 1.0f : 0.0f;
        vec[64] = 0.50f;
        vec[66] = 0.20f;

        // 5. Provenance & Metadata (67-79)
        String pUpper = (provenance != null ? provenance.toUpperCase() : "UNKNOWN");
        switch (pUpper) {
            case "SYSTEM_IMAGE": vec[67] = 1.0f; break;
            case "UPDATED_SYSTEM_APP": vec[68] = 1.0f; break;
            case "VERIFIED_STORE": vec[69] = 1.0f; break;
            case "CONFIRMED_LOCAL_APK": vec[70] = 1.0f; break;
            case "DOWNLOADED_APK": vec[71] = 1.0f; break;
            case "RESTORED_OEM": vec[72] = 1.0f; break;
            default: vec[73] = 1.0f; break; // UNKNOWN
        }

        boolean isUntrusted = (vec[71] == 1.0f || vec[73] == 1.0f || vec[70] == 1.0f);
        int targetSdk = manifest.targetSdkVersion;
        int minSdk = manifest.minSdkVersion;

        vec[74] = Math.min((float) targetSdk / 35.0f, 1.0f);
        vec[75] = (targetSdk <= 22) ? 1.0f : 0.0f;
        vec[76] = (targetSdk <= 28) ? 1.0f : 0.0f;
        vec[77] = Math.min((float) minSdk / 35.0f, 1.0f);

        boolean isSystem = (vec[67] == 1.0f || vec[68] == 1.0f);
        String label = (manifest.appLabel + " " + arscContent).toLowerCase();
        String[] brands = {"google service", "google play", "system update", "google framework", "android system",
                           "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"};
        boolean impersonates = false;
        if (!isSystem && !isKnownPub) {
            for (String b : brands) {
                if (label.contains(b) && !pkgName.contains(b.split(" ")[0])) {
                    impersonates = true;
                    break;
                }
            }
        }
        vec[78] = impersonates ? 1.0f : 0.0f;

        String[] suspTokens = {"reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan"};
        boolean hasSuspToken = false;
        for (String t : suspTokens) {
            if (pkgName.contains(t)) {
                hasSuspToken = true;
                break;
            }
        }
        vec[79] = (hasSuspToken && !isKnownPub) ? 1.0f : 0.0f;

        // 6. Joint Tells (80-83)
        boolean hasRatDex = (vec[34] == 1.0f || vec[38] == 1.0f || vec[40] == 1.0f);
        boolean hasRatPerms = (readSms || vec[3] == 1.0f);
        if (hasRatDex && isUntrusted && vec[75] == 1.0f && hasRatPerms) vec[80] = 1.0f;
        if (vec[25] == 1.0f && isUntrusted && (readSms || vec[5] == 1.0f)) vec[81] = 1.0f;
        if ((vec[16] == 1.0f || vec[17] == 1.0f) && (vec[36] == 1.0f || vec[42] == 1.0f) && isUntrusted) vec[82] = 1.0f;
        if (vec[24] == 1.0f && isUntrusted && (vec[58] == 0.0f || vec[52] == 1.0f) && vec[39] == 1.0f) vec[83] = 1.0f;

        // 7. Structural Forensics (84-91)
        boolean isThinDex = (totalDexSize > 0 && totalDexSize < 40000 && hasNativeLib);
        boolean isCorroboratedPacked = (maxAssetEntropy >= 7.80 && (vec[36] == 1.0f || isThinDex || vec[37] == 1.0f || zipTampered));

        vec[84] = zipTampered ? 1.0f : 0.0f;
        vec[85] = isCorroboratedPacked ? 1.0f : 0.0f;
        vec[86] = isThinDex ? 1.0f : 0.0f;
        vec[87] = hasNativeLib ? 1.0f : 0.0f;
        vec[88] = Math.min((float) htmlCardMentions / 20.0f, 1.0f);
        if (isCorroboratedPacked && readSms && isUntrusted) vec[89] = 1.0f;
        if (zipTampered && isThinDex && (vec[16] == 1.0f || vec[17] == 1.0f || vec[36] == 1.0f)) vec[90] = 1.0f;
        vec[91] = Math.min((float) pkgName.split("\\.").length / 8.0f, 1.0f);

        return vec;
    }

    public static void main(String[] args) throws Exception {
        String apkPath = args.length > 0 ? args[0] : "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk";
        String prov = args.length > 1 ? args[1] : "UNKNOWN";
        float[] vec = extractFromApk(apkPath, prov);
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < vec.length; i++) {
            sb.append(String.format(Locale.US, "%.4f", vec[i]));
            if (i < vec.length - 1) sb.append(", ");
        }
        sb.append("]");
        System.out.println(sb.toString());
    }
}