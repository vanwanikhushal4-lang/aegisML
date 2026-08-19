from androguard.core.apk import APK
from androguard.core.dex import DEX
apk_path = r"C:\Users\user\Downloads\androrat\AndroRAT\malware.apk"
a = APK(apk_path)
dex_strings = set()
for dex_bytes in a.get_all_dex():
    d = DEX(dex_bytes)
    for s in d.get_strings():
        dex_strings.add(s)

targets = ['content://sms', 'content://call_log', 'ProcessBuilder', 'Socket', 'getDeviceId', 'getSubscriberId', 'su', '/system/bin/sh', 'DexClassLoader', 'Base64', 'AccessibilityNodeInfo', 'sendTextMessage']
print('Total DEX strings found in real malware.apk:', len(dex_strings))
for t in targets:
    found = any(t in s for s in dex_strings)
    print(f'  Target "{t}": {found}')