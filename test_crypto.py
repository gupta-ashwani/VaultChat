"""
test_crypto.py — Phase 2 Unit Tests
=====================================
Tests the full cryptographic pipeline end-to-end:
  1. Key generation
  2. AES encrypt / decrypt standalone
  3. RSA key wrap / unwrap standalone
  4. Full XML message: build_secure_message → parse_secure_message
  5. Tamper detection (digest mismatch)
  6. Wrong key detection
"""

import sys
import os
import base64
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    generate_rsa_keypair, private_key_to_pem, public_key_to_pem,
    pem_to_private_key, pem_to_public_key,
    aes_encrypt, aes_decrypt,
    rsa_wrap_key, rsa_unwrap_key,
    build_secure_message, parse_secure_message,
    generate_and_save_keys, load_private_key, load_public_key,
)

PASS = "[PASS]"
FAIL = "[FAIL]"

def run(label, fn):
    try:
        fn()
        print(f"  {PASS}  {label}")
        return True
    except Exception as e:
        print(f"  {FAIL}  {label}")
        print(f"         Error: {e}")
        return False

results = []

print("\n" + "="*60)
print("  Phase 2 — Cryptographic Module Tests")
print("="*60)

# ── Test 1: RSA Key Generation ────────────────────────────────────────────────
def test_keygen():
    priv, pub = generate_rsa_keypair()
    priv_pem  = private_key_to_pem(priv)
    pub_pem   = public_key_to_pem(pub)
    assert "-----BEGIN RSA PRIVATE KEY-----" in priv_pem
    assert "-----BEGIN PUBLIC KEY-----" in pub_pem
    # Round-trip serialization
    priv2 = pem_to_private_key(priv_pem)
    pub2  = pem_to_public_key(pub_pem)
    assert private_key_to_pem(priv2) == priv_pem
    assert public_key_to_pem(pub2)  == pub_pem
results.append(run("RSA Key Generation & PEM round-trip", test_keygen))

# ── Test 2: AES Encrypt / Decrypt ────────────────────────────────────────────
def test_aes():
    key  = os.urandom(32)
    msg  = "Hello from AES-256-CBC! こんにちは 🔒"
    iv, ct   = aes_encrypt(msg, key)
    assert iv and ct, "iv and ciphertext must not be empty"
    recovered = aes_decrypt(iv, ct, key)
    assert recovered == msg, f"Expected '{msg}', got '{recovered}'"
results.append(run("AES-256-CBC Encrypt → Decrypt", test_aes))

# ── Test 3: RSA Key Wrap / Unwrap ────────────────────────────────────────────
def test_rsa_wrap():
    priv, pub  = generate_rsa_keypair()
    aes_key    = os.urandom(32)
    wrapped    = rsa_wrap_key(aes_key, pub)
    assert wrapped != aes_key
    unwrapped  = rsa_unwrap_key(wrapped, priv)
    assert unwrapped == aes_key, "Unwrapped key doesn't match original"
results.append(run("RSA-OAEP Key Wrap → Unwrap", test_rsa_wrap))

# ── Test 4: Full Secure XML Message Pipeline ──────────────────────────────────
def test_full_pipeline():
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv,   bob_pub   = generate_rsa_keypair()

    plaintext = "Alice to Bob: Meet me at the library at 6pm. This message is E2E encrypted!"

    xml_str = build_secure_message(
        plaintext_msg       = plaintext,
        sender_username     = "alice",
        sender_private_key  = alice_priv,
        receiver_public_key = bob_pub,
    )

    # Make sure it's valid XML and has the right structure
    from lxml import etree
    root = etree.fromstring(xml_str.encode("utf-8"))
    assert root.tag == "SecureMessage"
    assert root.find("{http://www.w3.org/2001/04/xmlenc#}EncryptedData") is not None
    assert root.find("{http://www.w3.org/2000/09/xmldsig#}Signature")   is not None

    result = parse_secure_message(xml_str, bob_priv, alice_pub)
    assert result["signature_valid"] == True
    assert result["plaintext"]       == plaintext
    assert result["sender"]          == "alice"
results.append(run("Full XML pipeline: build_secure_message → parse_secure_message", test_full_pipeline))

# ── Test 5: Tamper Detection ──────────────────────────────────────────────────
def test_tamper_detection():
    alice_priv, alice_pub = generate_rsa_keypair()
    _, bob_pub            = generate_rsa_keypair()
    bob_priv, _           = generate_rsa_keypair()

    xml_str = build_secure_message("Secret message", "alice", alice_priv, bob_pub)

    # Tamper: flip one byte of the CipherValue
    tampered = xml_str.replace("<xenc:CipherValue>", "<xenc:CipherValue>TAMPERED")

    caught = False
    try:
        parse_secure_message(tampered, bob_priv, alice_pub)
    except ValueError as e:
        caught = True
    assert caught, "Tampered XML should have been rejected"
results.append(run("Tamper detection (modified ciphertext caught)", test_tamper_detection))

# ── Test 6: Wrong Private Key Rejected ───────────────────────────────────────
def test_wrong_key():
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv,   bob_pub   = generate_rsa_keypair()
    charlie_priv, _       = generate_rsa_keypair()  # attacker

    xml_str = build_secure_message("For Bob's eyes only", "alice", alice_priv, bob_pub)

    caught = False
    try:
        # Charlie tries to decrypt Bob's message
        parse_secure_message(xml_str, charlie_priv, alice_pub)
    except Exception:
        caught = True
    assert caught, "Wrong private key should cause decryption failure"
results.append(run("Wrong receiver private key rejected", test_wrong_key))

# ── Test 7: Key File Save / Load ─────────────────────────────────────────────
def test_key_files():
    priv_pem, pub_pem = generate_and_save_keys("testuser", keys_dir="test_keys")
    priv = load_private_key("testuser", keys_dir="test_keys")
    pub  = load_public_key("testuser",  keys_dir="test_keys")
    # Sign and verify a test payload to confirm keys loaded correctly
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    sig = priv.sign(b"testdata", asym_padding.PKCS1v15(), hashes.SHA256())
    pub.verify(sig, b"testdata", asym_padding.PKCS1v15(), hashes.SHA256())
    # Cleanup
    import shutil
    shutil.rmtree("test_keys", ignore_errors=True)
results.append(run("Key save to disk and load from disk", test_key_files))

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "="*60)
passed = sum(results)
total  = len(results)
print(f"  Results: {passed}/{total} tests passed")
print("="*60)

if passed < total:
    sys.exit(1)
