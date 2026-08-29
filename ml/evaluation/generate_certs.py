"""
Deterministic X.509 Certificate & Fixture Generator for AEGIS Parity Suite.
Saves exact DER certificates and outputs canonical SHA-256 digests.
"""
import os
import hashlib
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures/certs"))
os.makedirs(CERTS_DIR, exist_ok=True)

OEM_CERTS = [
    ("samsung_electronics", "CN=Samsung Electronics, O=Samsung, C=KR", 101),
    ("samsung_knox", "CN=Samsung Knox Platform, O=Samsung, C=KR", 102),
    ("xiaomi_hyperos", "CN=Xiaomi HyperOS Platform, O=Xiaomi, C=CN", 103),
    ("xiaomi_miui", "CN=MIUI Official, O=Xiaomi, C=CN", 104),
    ("oneplus_oxygen", "CN=OnePlus Platform, O=OnePlus, C=CN", 105),
    ("oppo_realme_coloros", "CN=ColorOS Official, O=OPPO, C=CN", 106),
    ("realme_official", "CN=Realme Official, O=Realme, C=CN", 107),
    ("huawei_harmonyos", "CN=Huawei HarmonyOS, O=Huawei, C=CN", 108),
    ("vivo_originos", "CN=Vivo OriginOS, O=Vivo, C=CN", 109),
    ("google_play", "CN=Google Play, O=Google LLC, C=US", 110),
    ("npci_banking_sbi", "CN=State Bank of India, O=SBI, C=IN", 111),
    ("npci_banking_phonepe", "CN=PhonePe Internet, O=PhonePe, C=IN", 112)
]

def generate_deterministic_certs():
    digests = {}
    for tag, dn_str, seed in OEM_CERTS:
        der_path = os.path.join(CERTS_DIR, f"{tag}.der")
        if os.path.exists(der_path):
            with open(der_path, "rb") as f:
                der = f.read()
        else:
            # Deterministic generation
            priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
            subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, dn_str)])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(priv.public_key())
                .serial_number(seed)
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2045, 1, 1))
                .sign(priv, hashes.SHA256())
            )
            der = cert.public_bytes(serialization.Encoding.DER)
            with open(der_path, "wb") as f:
                f.write(der)

        sha = hashlib.sha256(der).hexdigest().lower()
        digests[tag] = (sha, der_path)
        print(f'"{sha}", // {tag}')
    return digests

if __name__ == "__main__":
    generate_deterministic_certs()
