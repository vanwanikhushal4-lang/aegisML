import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class HardenedZipReader {
    public static class Entry {
        public String name;
        public byte[] data;
        public boolean isEncryptedFlag;
        public int size;
    }

    public static List<Entry> readApk(File file) throws IOException {
        List<Entry> entries = new ArrayList<>();
        byte[] apkBytes = java.nio.file.Files.readAllBytes(file.toPath());
        ByteBuffer buf = ByteBuffer.wrap(apkBytes).order(ByteOrder.LITTLE_ENDIAN);

        int pos = 0;
        int len = apkBytes.length;

        // Scan for Local File Headers (0x04034b50)
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
                    String name = new String(nameBytes, "UTF-8");

                    int dataStart = nameStart + nameLen + extraLen;
                    byte[] data = new byte[0];

                    if (cSize > 0 && dataStart + cSize <= len) {
                        byte[] compData = new byte[cSize];
                        System.arraycopy(apkBytes, dataStart, compData, 0, cSize);

                        if (method == 0) { // STORED
                            data = compData;
                        } else if (method == 8) { // DEFLATED
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
                            } catch (Exception ex) {
                                // Fallback
                            }
                        }
                    }

                    Entry e = new Entry();
                    e.name = name;
                    e.data = data;
                    e.size = (data != null ? data.length : 0);
                    e.isEncryptedFlag = (flags & 0x0001) != 0;
                    entries.add(e);
                }
                pos += 30 + nameLen + extraLen + (cSize > 0 ? cSize : 0);
            } else {
                pos++;
            }
        }
        return entries;
    }

    public static void main(String[] args) throws Exception {
        File apk = new File("C:/Users/user/Downloads/60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk");
        List<Entry> entries = readApk(apk);
        System.out.println("Hardened Zip Reader read " + entries.size() + " entries successfully from anti-analysis APK!");
        for (Entry e : entries) {
            if (e.name.endsWith(".dex") || e.name.startsWith("assets/") || e.name.endsWith(".so")) {
                System.out.println("  * " + e.name + " (" + e.size + " bytes, encryptedBit=" + e.isEncryptedFlag + ")");
            }
        }
    }
}