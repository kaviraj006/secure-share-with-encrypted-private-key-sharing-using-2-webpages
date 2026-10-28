import json
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

def test_aes_gcm_roundtrip_and_tamper():
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12
    data = b"Plaintext zero knowledge payload"
    aad = b"SecureShare-AAD"

    # Encrypt
    ct = aesgcm.encrypt(nonce, data, aad)
    # Decrypt
    pt = aesgcm.decrypt(nonce, ct, aad)
    assert pt == data

    # 1 byte corruption in ciphertext rejects with InvalidTag
    corrupted_ct = bytearray(ct)
    corrupted_ct[0] ^= 0x01
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, bytes(corrupted_ct), aad)

    # 1 byte corruption in AAD rejects
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, ct, b"Tampered-AAD")

    # Wrong key rejects
    wrong_key = AESGCM.generate_key(bit_length=256)
    with pytest.raises(InvalidTag):
        AESGCM(wrong_key).decrypt(nonce, ct, aad)

    # Wrong nonce rejects
    with pytest.raises(InvalidTag):
        aesgcm.decrypt(b"\x01" * 12, ct, aad)

def test_x25519_key_agreement():
    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    shared_alice = alice_private.exchange(bob_public)
    shared_bob = bob_private.exchange(alice_public)

    assert shared_alice == shared_bob
    assert len(shared_alice) == 32

def test_ed25519_signatures_and_tamper_rejection():
    sender_sk = ed25519.Ed25519PrivateKey.generate()
    sender_pk = sender_sk.public_key()

    message = b"Canonical SecureShare Envelope V1"
    signature = sender_sk.sign(message)

    # Valid verification
    sender_pk.verify(signature, message)

    # Tampered message rejects
    with pytest.raises(InvalidSignature):
        sender_pk.verify(signature, b"Tampered Message")

    # Corrupted signature rejects
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0xFF
    with pytest.raises(InvalidSignature):
        sender_pk.verify(bytes(tampered_sig), message)

def test_hkdf_sha256_derivation():
    shared_secret = b"\x42" * 32
    salt = b"\x11" * 32
    info = b"SecureShare-v1|wrapping-key|sender|recipient|transfer|prekey"

    hkdf1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key1 = hkdf1.derive(shared_secret)

    hkdf2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key2 = hkdf2.derive(shared_secret)

    assert key1 == key2
    assert len(key1) == 32
