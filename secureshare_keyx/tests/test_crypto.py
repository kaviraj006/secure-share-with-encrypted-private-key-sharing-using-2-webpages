import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

def test_x25519_diffie_hellman():
    alice_sk = x25519.X25519PrivateKey.generate()
    bob_sk = x25519.X25519PrivateKey.generate()
    
    shared_a = alice_sk.exchange(bob_sk.public_key())
    shared_b = bob_sk.exchange(alice_sk.public_key())
    
    assert shared_a == shared_b
    assert len(shared_a) == 32

def test_hkdf_wrapping_key_derivation():
    shared_secret = b"\x55" * 32
    salt = b"\x77" * 32
    info = b"SecureShare-v1|wrapping-key|sender|recipient|tx_test|prekey_test"
    
    hkdf1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key1 = hkdf1.derive(shared_secret)
    
    hkdf2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key2 = hkdf2.derive(shared_secret)
    
    assert key1 == key2
    assert len(key1) == 32

def test_ed25519_signatures_and_tamper_rejection():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    
    msg = b"Canonical Envelope Data V1"
    sig = sk.sign(msg)
    pk.verify(sig, msg)
    
    with pytest.raises(InvalidSignature):
        pk.verify(sig, b"Tampered Envelope Data")

def test_aes_gcm_envelope_wrapping():
    raw_aes_file_key = b"\x99" * 32
    wrapping_key = AESGCM.generate_key(bit_length=256)
    nonce = b"\x12" * 12
    aad = b"SecureShare-Envelope-Key-v1|tx_123|prekey_456"
    
    ct = AESGCM(wrapping_key).encrypt(nonce, raw_aes_file_key, aad)
    pt = AESGCM(wrapping_key).decrypt(nonce, ct, aad)
    assert pt == raw_aes_file_key
    
    with pytest.raises(InvalidTag):
        AESGCM(wrapping_key).decrypt(nonce, ct, b"Wrong-AAD")
