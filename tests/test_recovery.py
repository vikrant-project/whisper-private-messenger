import os
import json
import pytest
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(passphrase.encode("utf-8"))

def test_recovery_encryption_and_decryption_flow():
    passphrase = "SuperSecureCorrectPassphrase!99"
    identity_bundle = {
        "username": "satoshi",
        "identityPublicKeyHex": "11" * 32,
        "identitySecretKeyHex": "22" * 64,
        "preKeyPublicHex": "33" * 32,
        "preKeySecretHex": "44" * 32
    }
    
    # 1. Export encrypted backup
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(passphrase, salt, iterations=100000)
    
    plaintext = json.dumps(identity_bundle).encode("utf-8")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    backup_file = {
        "format": "whisper-encrypted-identity",
        "version": 1,
        "username": "satoshi",
        "kdf": "PBKDF2-SHA256",
        "iterations": 100000,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }
    
    # 2. Restore with correct passphrase
    restore_key = derive_key(passphrase, bytes.fromhex(backup_file["salt"]), backup_file["iterations"])
    restore_aesgcm = AESGCM(restore_key)
    decrypted_bytes = restore_aesgcm.decrypt(
        bytes.fromhex(backup_file["iv"]),
        bytes.fromhex(backup_file["ciphertext"]),
        None
    )
    restored = json.loads(decrypted_bytes.decode("utf-8"))
    assert restored["username"] == "satoshi"
    assert restored["identitySecretKeyHex"] == "22" * 64

def test_recovery_wrong_passphrase_fails():
    passphrase = "CorrectPassphrase123!"
    wrong_passphrase = "WrongPassphrase456!"
    
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(passphrase, salt)
    
    plaintext = b'{"secret": "confidential_key"}'
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    wrong_key = derive_key(wrong_passphrase, salt)
    wrong_aesgcm = AESGCM(wrong_key)
    
    with pytest.raises(Exception):
        wrong_aesgcm.decrypt(iv, ciphertext, None)
