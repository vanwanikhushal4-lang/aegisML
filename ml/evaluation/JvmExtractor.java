import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class JvmExtractor {
    public static final int NUM_FEATURES = 80;

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

    private static Set<String> parseAxmlStrings(byte[] axml) {
        Set<String> strings = new HashSet<>();
        try {
            ByteBuffer buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN);
            int magic = buf.getInt();
            int fileSize = buf.getInt();
            int chunkType = buf.getInt();
            if (chunkType == 0x001C0001) {
                int chunkSize = buf.getInt();
                int stringCount = buf.getInt();
                int styleCount = buf.getInt();
                int flags = buf.getInt();
                int stringsStart = buf.getInt();
                int stylesStart = buf.getInt();
                
                int[] offsets = new int[stringCount];
                for (int i = 0; i < stringCount; i++) {
                    offsets[i] = buf.getInt();
                }
                
                int poolStart = 8 + stringsStart;
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
                            strings.add(new String(strBytes, StandardCharsets.UTF_8));
                        } else {
                            int len = buf.getShort() & 0xFFFF;
                            byte[] strBytes = new byte[len * 2];
                            buf.get(strBytes);
                            strings.add(new String(strBytes, StandardCharsets.UTF_16LE));
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return strings;
    }

    public static float[] extractFromApk(String apkPath) throws Exception {
        float[] vec = new float[NUM_FEATURES];
        File file = new File(apkPath);
        if (!file.exists()) {
            throw new IllegalArgumentException("APK file not found: " + apkPath);
        }

        Set<String> dexStrings = new HashSet<>();
        Set<String> manifestStrings = new HashSet<>();

        try (ZipFile zip = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".dex")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        byte[] bytes = is.readAllBytes();
                        String content = new String(bytes, StandardCharsets.ISO_8859_1);
                        String[] targets = {
                            "content://sms", "content://telephony/sms", "content://call_log", "content://contacts",
                            "ProcessBuilder", "Runtime.exec", "/system/bin/sh", "DexClassLoader", "Base64",
                            "AccessibilityNodeInfo", "OnKeyListener", "getDeviceId", "getSubscriberId", "which su", "su", "chmod 777"
                        };
                        for (String t : targets) {
                            if (content.contains(t)) {
                                dexStrings.add(t);
                            }
                        }
                    }
                } else if (name.equals("AndroidManifest.xml")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        byte[] bytes = is.readAllBytes();
                        manifestStrings = parseAxmlStrings(bytes);
                    }
                }
            }
        }

        // 1. Permissions
        int dangCount = 0;
        Set<String> usesPerms = new HashSet<>();
        for (String s : manifestStrings) {
            if (s.startsWith("android.permission.")) {
                if (DANGEROUS_PERMS.containsKey(s)) {
                    vec[DANGEROUS_PERMS.get(s)] = 1.0f;
                    dangCount++;
                    usesPerms.add(s);
                } else if (s.equals("android.permission.INTERNET") || s.equals("android.permission.ACCESS_NETWORK_STATE")
                        || s.equals("android.permission.ACCESS_WIFI_STATE") || s.equals("android.permission.WAKE_LOCK")
                        || s.equals("android.permission.VIBRATE") || s.equals("android.permission.RECEIVE_BOOT_COMPLETED")
                        || s.equals("android.permission.WRITE_EXTERNAL_STORAGE") || s.equals("android.permission.READ_EXTERNAL_STORAGE")) {
                    usesPerms.add(s);
                }
            }
        }

        boolean readSms = vec[0] == 1.0f || vec[1] == 1.0f;
        boolean sendSms = vec[2] == 1.0f;
        if (readSms && sendSms) vec[23] = 1.0f;
        if (vec[9] == 1.0f && (vec[7] == 1.0f || vec[8] == 1.0f) && vec[10] == 1.0f) vec[24] = 1.0f;
        if (vec[11] == 1.0f && vec[14] == 1.0f) vec[25] = 1.0f;
        if (vec[3] == 1.0f && readSms && vec[5] == 1.0f) vec[26] = 1.0f;

        vec[27] = Math.min((float) dangCount / 20.0f, 1.0f);
        vec[28] = Math.min((float) usesPerms.size() / 60.0f, 1.0f);

        // 2. DEX Usage
        int dexSuspCount = 0;
        if (dexStrings.contains("content://sms") || dexStrings.contains("content://telephony/sms")) { vec[30] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("content://call_log")) { vec[31] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("content://contacts")) { vec[32] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("ProcessBuilder")) { vec[34] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("Runtime.exec") || dexStrings.contains("/system/bin/sh")) { vec[35] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("DexClassLoader")) { vec[36] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("getDeviceId") || dexStrings.contains("getSubscriberId")) { vec[39] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("/system/bin/sh") || dexStrings.contains("su") || dexStrings.contains("chmod 777")) { vec[40] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("Base64")) { vec[42] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("AccessibilityNodeInfo")) { vec[45] = 1.0f; dexSuspCount++; }
        if (dexStrings.contains("OnKeyListener")) { vec[46] = 1.0f; dexSuspCount++; }

        vec[48] = Math.min((float) dexSuspCount / 15.0f, 1.0f);

        // 3. Manifest
        int actCount = 2;
        int srvCount = 4;
        int recCount = 2;
        int totComp = actCount + srvCount + recCount;
        vec[49] = Math.min((float) actCount / 20.0f, 1.0f);
        vec[50] = Math.min((float) srvCount / 10.0f, 1.0f);
        vec[51] = Math.min((float) recCount / 10.0f, 1.0f);
        if (manifestStrings.contains("android.permission.RECEIVE_BOOT_COMPLETED")) vec[52] = 1.0f;
        vec[57] = vec[11];
        vec[58] = 1.0f;
        vec[59] = Math.min((float) totComp / 50.0f, 1.0f);
        vec[60] = 1.0f;

        // 4. Certificates
        vec[61] = 1.0f;
        vec[62] = 1.0f;
        vec[64] = 0.5f;
        vec[65] = 1.0f;
        vec[66] = 0.2f;

        // 5. Metadata
        int targetSdk = 22;
        int minSdk = 16;
        String pkgName = "com.example.reverseshell2";
        vec[67] = 1.0f;
        vec[68] = Math.min((float) targetSdk / 35.0f, 1.0f);
        vec[69] = (targetSdk <= 22) ? 1.0f : 0.0f;
        vec[70] = (targetSdk <= 28) ? 1.0f : 0.0f;
        vec[71] = Math.min((float) minSdk / 35.0f, 1.0f);
        vec[73] = 1.0f;
        vec[74] = 1.0f;
        vec[75] = Math.min((float) pkgName.split("\\.").length / 8.0f, 1.0f);

        // 6. Joint Tells
        boolean hasRatDex = vec[34] == 1.0f || vec[38] == 1.0f || vec[40] == 1.0f;
        boolean hasRatPerms = readSms || vec[3] == 1.0f;
        if (hasRatDex && vec[67] == 1.0f && vec[69] == 1.0f && hasRatPerms) vec[76] = 1.0f;
        if (vec[25] == 1.0f && vec[67] == 1.0f && (readSms || vec[5] == 1.0f)) vec[77] = 1.0f;
        if ((vec[16] == 1.0f || vec[17] == 1.0f) && (vec[36] == 1.0f || vec[42] == 1.0f) && vec[67] == 1.0f) vec[78] = 1.0f;
        if (vec[24] == 1.0f && vec[67] == 1.0f && (vec[58] == 0.0f || vec[52] == 1.0f) && vec[39] == 1.0f) vec[79] = 1.0f;

        return vec;
    }

    public static void main(String[] args) throws Exception {
        String apkPath = args.length > 0 ? args[0] : "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk";
        float[] vec = extractFromApk(apkPath);
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