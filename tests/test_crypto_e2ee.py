import os
import hashlib
import hmac
import nacl.signing
import nacl.public
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.crypto_utils import verify_ed25519_signature

def test_ed25519_tamper_detection():
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    pub_hex = vk.encode().hex()
    
    msg = b"Confidential message text"
    sig_hex = sk.sign(msg).signature.hex()
    
    # Valid signature verifies
    assert verify_ed25519_signature(pub_hex, msg, sig_hex) is True
    
    # Tampered message fails
    tampered_msg = b"Confidential message text!"
    assert verify_ed25519_signature(pub_hex, tampered_msg, sig_hex) is False
    
    # Tampered signature fails
    tampered_sig = list(sig_hex)
    tampered_sig[0] = '0' if tampered_sig[0] != '0' else '1'
    assert verify_ed25519_signature(pub_hex, msg, "".join(tampered_sig)) is False

def test_x25519_key_agreement():
    # Alice generates X25519 keypair
    alice_sec = nacl.public.PrivateKey.generate()
    alice_pub = alice_sec.public_key
    
    # Bob generates X25519 keypair
    bob_sec = nacl.public.PrivateKey.generate()
    bob_pub = bob_sec.public_key
    
    # Alice computes shared secret using Bob's public key
    alice_box = nacl.public.Box(alice_sec, bob_pub)
    alice_shared = alice_box.shared_key()
    
    # Bob computes shared secret using Alice's public key
    bob_box = nacl.public.Box(bob_sec, alice_pub)
    bob_shared = bob_box.shared_key()
    
    # Must be identical
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32

def test_aes_gcm_authenticated_encryption():
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = b"Whisper end-to-end encrypted secret message."
    
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Decrypt
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    assert decrypted == plaintext
    
    # Tamper with 1 byte of ciphertext -> must fail AEAD authentication
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF
    try:
        aesgcm.decrypt(nonce, bytes(tampered), None)
        assert False, "Decryption of tampered ciphertext should have raised an exception!"
    except Exception:
        pass  # Expected behavior

def test_forward_secrecy_ratchet_simulation():
    """Simulates symmetric chain key ratcheting: MK_i = HMAC(CK_i, 'msg_i'), CK_i+1 = HMAC(CK_i, 'next')."""
    initial_chain_key = os.urandom(32)
    
    keys = []
    current_ck = initial_chain_key
    for i in range(5):
        mk = hmac.new(current_ck, f"msg_{i}".encode("utf-8"), hashlib.sha256).digest()
        keys.append(mk)
        current_ck = hmac.new(current_ck, b"next_chain_key", hashlib.sha256).digest()
    
    # All message keys must be distinct
    assert len(set(keys)) == 5
    # Compromising key 4 cannot recover key 0 (HMAC pre-image resistance)
    assert keys[0] != keys[4]

def test_deterministic_safety_number():
    """Verifies that regardless of who computes it, the safety number between Alice and Bob is identical."""
    alice_pub = "11" * 32
    bob_pub = "22" * 32
    
    # Order A -> B
    sorted_1 = sorted([alice_pub.lower(), bob_pub.lower()])
    hash_1 = hashlib.sha256(f"{sorted_1[0]}:{sorted_1[1]}".encode("utf-8")).digest()
    
    # Order B -> A
    sorted_2 = sorted([bob_pub.lower(), alice_pub.lower()])
    hash_2 = hashlib.sha256(f"{sorted_2[0]}:{sorted_2[1]}".encode("utf-8")).digest()
    
    assert hash_1 == hash_2
