import json
import os
import random
from typing import List, Dict, Any

random.seed(42)
OUTPUT_DIR = os.path.dirname(__file__)

ALLOWLIST_APPS = [
    {
        'package_name': 'com.sbi.lotusintouch',
        'app_name': 'YONO SBI',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 24,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION', 'android.permission.READ_PHONE_STATE',
            'android.permission.CAMERA', 'android.permission.USE_BIOMETRIC',
            'android.permission.READ_CONTACTS', 'android.permission.POST_NOTIFICATIONS'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://sbiyono.sbi', 'javax.crypto.Cipher', 'androidx.biometric.BiometricPrompt',
            'okhttp3.OkHttpClient', 'content://contacts'
        ],
        'manifest': {
            'exported_activities': 2, 'exported_services': 0, 'exported_receivers': 1,
            'has_boot_receiver': False, 'has_sms_receiver': False, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 24
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 30.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'com.phonepe.app',
        'app_name': 'PhonePe: Secure Payments',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 23,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_PHONE_STATE', 'android.permission.CAMERA',
            'android.permission.READ_CONTACTS', 'android.permission.USE_BIOMETRIC',
            'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://phonepe.com', 'android.telephony.SmsManager', 'content://sms',
            'androidx.camera.view.PreviewView', 'javax.crypto.Cipher'
        ],
        'manifest': {
            'exported_activities': 3, 'exported_services': 1, 'exported_receivers': 2,
            'has_boot_receiver': False, 'has_sms_receiver': True, 'has_foreground_service': True,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 32
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 25.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'net.one97.paytm',
        'app_name': 'Paytm: Secure UPI Payments',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 23,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_PHONE_STATE', 'android.permission.CAMERA',
            'android.permission.READ_CONTACTS', 'android.permission.USE_BIOMETRIC',
            'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://paytm.com', 'android.telephony.SmsManager', 'content://sms',
            'androidx.security.crypto.EncryptedSharedPreferences'
        ],
        'manifest': {
            'exported_activities': 4, 'exported_services': 2, 'exported_receivers': 2,
            'has_boot_receiver': False, 'has_sms_receiver': True, 'has_foreground_service': True,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 40
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 25.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'com.google.android.apps.nbu.paisa.user',
        'app_name': 'Google Pay: Save and Pay',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 23,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_PHONE_STATE', 'android.permission.CAMERA',
            'android.permission.READ_CONTACTS', 'android.permission.USE_BIOMETRIC'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://pay.google.com', 'com.google.android.gms', 'javax.crypto.Cipher'
        ],
        'manifest': {
            'exported_activities': 2, 'exported_services': 1, 'exported_receivers': 1,
            'has_boot_receiver': False, 'has_sms_receiver': False, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 28
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 30.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'com.whatsapp',
        'app_name': 'WhatsApp Messenger',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 21,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.CAMERA', 'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_CALL_LOG',
            'android.permission.READ_PHONE_STATE', 'android.permission.POST_NOTIFICATIONS'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://whatsapp.net', 'content://contacts', 'content://call_log', 'javax.crypto.Cipher',
            'org.whispersystems.curve25519'
        ],
        'manifest': {
            'exported_activities': 5, 'exported_services': 2, 'exported_receivers': 3,
            'has_boot_receiver': True, 'has_sms_receiver': False, 'has_foreground_service': True,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 45
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 25.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'com.ubercab',
        'app_name': 'Uber: Request a ride',
        'is_system_app': False,
        'is_sideloaded': False,
        'target_sdk': 34,
        'min_sdk': 24,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION', 'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.CAMERA', 'android.permission.READ_CONTACTS'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://uber.com', 'com.google.android.gms.location', 'okhttp3.OkHttpClient'
        ],
        'manifest': {
            'exported_activities': 3, 'exported_services': 1, 'exported_receivers': 1,
            'has_boot_receiver': False, 'has_sms_receiver': False, 'has_foreground_service': True,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 30
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': False, 'is_known_publisher': True,
            'validity_years': 25.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_allowlist',
        'release_year': 2023
    },
    {
        'package_name': 'com.enterprise.salescrm',
        'app_name': 'Velox Field CRM',
        'is_system_app': False,
        'is_sideloaded': True,
        'target_sdk': 33,
        'min_sdk': 26,
        'permissions': [
            'android.permission.INTERNET', 'android.permission.CAMERA', 'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS', 'android.permission.READ_CALL_LOG'
        ],
        'signature_permissions': [],
        'dex_strings': [
            'https://crm.veloxsolutions.com/api/v2', 'content://contacts', 'content://call_log',
            'retrofit2.Retrofit', 'androidx.room.Room'
        ],
        'manifest': {
            'exported_activities': 1, 'exported_services': 0, 'exported_receivers': 0,
            'has_boot_receiver': False, 'has_sms_receiver': False, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': 8
        },
        'certificate': {
            'is_debug_key': False, 'is_self_signed': True, 'is_known_publisher': False,
            'validity_years': 25.0, 'is_generic_issuer': False, 'cert_count': 1
        },
        'label': 0,
        'family': 'benign_sideloaded_business',
        'release_year': 2023
    }
]

ANDRORAT_ACCEPTANCE_SAMPLE = {
    'package_name': 'com.example.reverseshell2',
    'app_name': 'Google Service Framework',
    'is_system_app': False,
    'is_sideloaded': True,
    'target_sdk': 22,
    'min_sdk': 14,
    'permissions': [
        'android.permission.INTERNET', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS',
        'android.permission.SEND_SMS', 'android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION', 'android.permission.RECORD_AUDIO',
        'android.permission.CAMERA', 'android.permission.READ_PHONE_STATE'
    ],
    'signature_permissions': [],
    'dex_strings': [
        'content://sms', 'content://call_log', 'java.lang.ProcessBuilder',
        'java.net.Socket', '/system/bin/sh', 'getDeviceId', 'getSubscriberId',
        '192.168.1.105:4444', 'raw_c2_ip', 'hidden_camera_capture'
    ],
    'manifest': {
        'exported_activities': 1, 'exported_services': 2, 'exported_receivers': 2,
        'has_boot_receiver': True, 'has_sms_receiver': True, 'has_foreground_service': False,
        'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
        'has_launcher_activity': True, 'total_components': 5
    },
    'certificate': {
        'is_debug_key': True, 'is_self_signed': True, 'is_known_publisher': False,
        'validity_years': 30.0, 'is_generic_issuer': True, 'cert_count': 1
    },
    'label': 1,
    'family': 'rat_spyware',
    'release_year': 2024
}

def generate_synthetic_benign_app(app_id: int, release_year: int) -> Dict[str, Any]:
    categories = ['productivity', 'social', 'game', 'finance', 'utility', 'health', 'ecommerce']
    cat = random.choice(categories)
    is_sideloaded = random.random() < 0.12
    perms = ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE']
    if cat in ['social', 'productivity']:
        if random.random() < 0.7: perms.append('android.permission.CAMERA')
        if random.random() < 0.5: perms.append('android.permission.RECORD_AUDIO')
        if random.random() < 0.6: perms.append('android.permission.READ_CONTACTS')
        if random.random() < 0.4: perms.append('android.permission.ACCESS_FINE_LOCATION')
    elif cat in ['finance']:
        perms.extend(['android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_PHONE_STATE', 'android.permission.USE_BIOMETRIC'])
        if random.random() < 0.4: perms.extend(['android.permission.RECEIVE_SMS', 'android.permission.READ_SMS'])
    elif cat in ['utility']:
        if random.random() < 0.5: perms.append('android.permission.POST_NOTIFICATIONS')
        if random.random() < 0.3: perms.append('android.permission.WRITE_SETTINGS')
        
    dex = ['androidx.core.app.ComponentActivity', 'kotlinx.coroutines', 'retrofit2.Retrofit']
    if 'android.permission.READ_CONTACTS' in perms: dex.append('content://contacts')
    if 'android.permission.READ_SMS' in perms: dex.append('content://sms')
    if random.random() < 0.3: dex.append('javax.crypto.Cipher')
    if random.random() < 0.2: dex.append('java.lang.reflect.Method.invoke')

    target_sdk = random.choice([31, 32, 33, 34, 35])
    return {
        'package_name': f'com.{cat}.app{app_id}',
        'app_name': f'{cat.capitalize()} App {app_id}',
        'is_system_app': False,
        'is_sideloaded': is_sideloaded,
        'target_sdk': target_sdk,
        'min_sdk': random.choice([21, 24, 26]),
        'permissions': perms,
        'signature_permissions': [],
        'dex_strings': dex,
        'manifest': {
            'exported_activities': random.randint(1, 4),
            'exported_services': random.randint(0, 2),
            'exported_receivers': random.randint(0, 2),
            'has_boot_receiver': random.random() < 0.15,
            'has_sms_receiver': 'android.permission.RECEIVE_SMS' in perms,
            'has_foreground_service': random.random() < 0.2,
            'has_accessibility_service': False,
            'has_device_admin': False,
            'has_system_alert_window': random.random() < 0.05,
            'has_launcher_activity': True,
            'total_components': random.randint(5, 30)
        },
        'certificate': {
            'is_debug_key': False,
            'is_self_signed': is_sideloaded and random.random() < 0.5,
            'is_known_publisher': random.random() < 0.25 and not is_sideloaded,
            'validity_years': random.choice([25.0, 30.0, 40.0]),
            'is_generic_issuer': False,
            'cert_count': 1
        },
        'label': 0,
        'family': 'benign',
        'release_year': release_year
    }

def generate_synthetic_malware_app(app_id: int, family: str, release_year: int) -> Dict[str, Any]:
    target_sdk = random.choice([19, 21, 22, 23, 26, 28]) if release_year <= 2023 else random.choice([22, 28, 30, 32])
    is_sideloaded = random.random() < 0.95
    is_debug = random.random() < 0.65
    
    if family == 'rat_spyware':
        app_name = random.choice(['System Update Service', 'Google Play Security', 'Device Booster Pro', 'Battery Saver', 'WhatsApp Update'])
        pkg = f'com.example.reverseshell{app_id}' if random.random() < 0.5 else f'com.service.updater{app_id}'
        perms = [
            'android.permission.INTERNET', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS',
            'android.permission.SEND_SMS', 'android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION', 'android.permission.RECORD_AUDIO', 'android.permission.CAMERA',
            'android.permission.READ_PHONE_STATE'
        ]
        dex = [
            'content://sms', 'content://call_log', 'java.lang.ProcessBuilder', 'java.net.Socket',
            '/system/bin/sh', 'getDeviceId', 'getSubscriberId', '192.168.1.100:8888', 'raw_c2_ip',
            'android.telephony.SmsManager', 'hidden_camera_capture'
        ]
        manifest = {
            'exported_activities': 1, 'exported_services': 2, 'exported_receivers': 2,
            'has_boot_receiver': True, 'has_sms_receiver': True, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': random.random() < 0.4,
            'total_components': random.randint(4, 8)
        }
    elif family == 'banking_trojan':
        app_name = random.choice(['Flash Player 2024', 'SBI YONO Fast Update', 'HDFC NetBanking Quick', 'Fast Cleaner', 'Crypto Wallet Helper'])
        pkg = f'com.fast.cleaner.pro{app_id}'
        perms = [
            'android.permission.INTERNET', 'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS', 'android.permission.READ_PHONE_STATE',
            'android.permission.QUERY_ALL_PACKAGES'
        ]
        dex = [
            'content://sms', 'AccessibilityNodeInfo.performAction', 'ACTION_CLICK', 'AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED',
            'javax.crypto.Cipher', 'Base64.decode', 'https://c2-bank-stealer.xyz/gate.php'
        ]
        manifest = {
            'exported_activities': 2, 'exported_services': 3, 'exported_receivers': 2,
            'has_boot_receiver': True, 'has_sms_receiver': True, 'has_foreground_service': True,
            'has_accessibility_service': True, 'has_device_admin': random.random() < 0.6,
            'has_system_alert_window': True, 'has_launcher_activity': True, 'total_components': random.randint(6, 12)
        }
    elif family == 'dropper':
        app_name = random.choice(['Google Framework Helper', 'PDF Reader Pro', 'QR Code Scanner Plus'])
        pkg = f'com.utility.scanner{app_id}'
        perms = [
            'android.permission.INTERNET', 'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INSTALL_PACKAGES'
        ]
        dex = [
            'dalvik.system.DexClassLoader', 'Base64.decode', 'javax.crypto.Cipher', 'java.lang.reflect.Method.invoke',
            'InMemoryDexClassLoader'
        ]
        manifest = {
            'exported_activities': 1, 'exported_services': 1, 'exported_receivers': 1,
            'has_boot_receiver': True, 'has_sms_receiver': False, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': random.randint(3, 6)
        }
    else:
        app_name = random.choice(['Free Wallpaper HD', 'Super Game 2024', 'Funny Ringtones Pro'])
        pkg = f'com.game.fun{app_id}'
        perms = [
            'android.permission.INTERNET', 'android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS', 'android.permission.READ_PHONE_STATE'
        ]
        dex = [
            'android.telephony.SmsManager', 'sendTextMessage', 'content://sms', 'Base64.decode'
        ]
        manifest = {
            'exported_activities': 1, 'exported_services': 1, 'exported_receivers': 2,
            'has_boot_receiver': True, 'has_sms_receiver': True, 'has_foreground_service': False,
            'has_accessibility_service': False, 'has_device_admin': False, 'has_system_alert_window': False,
            'has_launcher_activity': True, 'total_components': random.randint(4, 7)
        }

    return {
        'package_name': pkg,
        'app_name': app_name,
        'is_system_app': False,
        'is_sideloaded': is_sideloaded,
        'target_sdk': target_sdk,
        'min_sdk': 19,
        'permissions': perms,
        'signature_permissions': [],
        'dex_strings': dex,
        'manifest': manifest,
        'certificate': {
            'is_debug_key': is_debug,
            'is_self_signed': True,
            'is_known_publisher': False,
            'validity_years': random.choice([20.0, 30.0]),
            'is_generic_issuer': is_debug,
            'cert_count': 1
        },
        'label': 1,
        'family': family,
        'release_year': release_year
    }

def generate_full_corpus():
    train_apps = []
    test_apps = []
    
    with open(os.path.join(OUTPUT_DIR, 'allowlist_gate_dataset.json'), 'w', encoding='utf-8') as f:
        json.dump(ALLOWLIST_APPS, f, indent=2)
        
    with open(os.path.join(OUTPUT_DIR, 'androrat_acceptance_sample.json'), 'w', encoding='utf-8') as f:
        json.dump(ANDRORAT_ACCEPTANCE_SAMPLE, f, indent=2)

    for i in range(1200):
        train_apps.append(generate_synthetic_benign_app(i, release_year=random.choice([2020, 2021, 2022, 2023])))
    for app in ALLOWLIST_APPS:
        train_apps.append(app)

    malware_families = ['rat_spyware', 'banking_trojan', 'dropper', 'sms_fraud']
    for i in range(400):
        fam = malware_families[i % len(malware_families)]
        train_apps.append(generate_synthetic_malware_app(i, fam, release_year=random.choice([2020, 2021, 2022, 2023])))

    random.shuffle(train_apps)
    with open(os.path.join(OUTPUT_DIR, 'train_dataset.json'), 'w', encoding='utf-8') as f:
        json.dump(train_apps, f, indent=2)

    for i in range(800):
        test_apps.append(generate_synthetic_benign_app(2000 + i, release_year=random.choice([2024, 2025])))
    for app in ALLOWLIST_APPS:
        test_apps.append(app)
        
    for i in range(80):
        fam = malware_families[i % len(malware_families)]
        test_apps.append(generate_synthetic_malware_app(1000 + i, fam, release_year=random.choice([2024, 2025])))

    test_apps.append(ANDRORAT_ACCEPTANCE_SAMPLE)

    random.shuffle(test_apps)
    with open(os.path.join(OUTPUT_DIR, 'test_holdout_dataset.json'), 'w', encoding='utf-8') as f:
        json.dump(test_apps, f, indent=2)

    print(f'Generated {len(train_apps)} training samples and {len(test_apps)} test holdout samples.')

if __name__ == '__main__':
    generate_full_corpus()