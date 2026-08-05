"""
crypto_utils.py — Phase 2 Core XML Security Module
====================================================
Implements W3C XML Security standards using the `cryptography` library:
  1. RSA key-pair generation & PEM serialization
  2. AES-256-CBC encryption (the actual message)
  3. RSA-OAEP key wrapping (encrypt the AES key with receiver's RSA public key)
  4. XML Canonicalization — C14N (Canonical XML 1.0)
  5. XML Digital Signature — RSA-SHA256 over C14N'd XML
  6. Signature Verification

XML format produced follows W3C XMLdsig & XMLenc standards:
  <SecureMessage>
    <xenc:EncryptedData>          ← AES-encrypted ciphertext
      <xenc:EncryptionMethod Algorithm="aes256-cbc"/>
      <ds:KeyInfo>
        <xenc:EncryptedKey>       ← RSA-OAEP wrapped AES key
          ...
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>...</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
    <ds:Signature>                ← RSA-SHA256 signature over the EncryptedData block
      <ds:SignedInfo>...</ds:SignedInfo>
      <ds:SignatureValue>...</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:KeyName>sender_username</ds:KeyName>
      </ds:KeyInfo>
    </ds:Signature>
  </SecureMessage>
"""

import os
import base64
import hashlib
from lxml import etree

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── W3C XML Security Namespaces ──────────────────────────────────────────────
NS_DS   = "http://www.w3.org/2000/09/xmldsig#"
NS_XENC = "http://www.w3.org/2001/04/xmlenc#"

NSMAP = {
    'ds':   NS_DS,
    'xenc': NS_XENC,
}

# ═════════════════════════════════════════════════════════════════════════════
# 1. KEY GENERATION & SERIALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def private_key_to_pem(private_key):
    """Serialize RSA private key to PEM string."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")


def public_key_to_pem(public_key):
    """Serialize RSA public key to PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def pem_to_private_key(pem_str):
    """Load RSA private key from PEM string."""
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)


def pem_to_public_key(pem_str):
    """Load RSA public key from PEM string."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def generate_and_save_keys(username, keys_dir="keys"):
    """
    Generate and save RSA key pair for a user to disk.
    Files: keys/<username>_private.pem, keys/<username>_public.pem
    Returns (private_key_pem, public_key_pem).
    """
    os.makedirs(keys_dir, exist_ok=True)
    priv, pub = generate_rsa_keypair()
    priv_pem = private_key_to_pem(priv)
    pub_pem  = public_key_to_pem(pub)

    with open(os.path.join(keys_dir, f"{username}_private.pem"), "w") as f:
        f.write(priv_pem)
    with open(os.path.join(keys_dir, f"{username}_public.pem"), "w") as f:
        f.write(pub_pem)

    print(f"[KeyGen] Keys saved for '{username}' in '{keys_dir}/'")
    return priv_pem, pub_pem


def load_private_key(username, keys_dir="keys"):
    path = os.path.join(keys_dir, f"{username}_private.pem")
    with open(path, "r") as f:
        return pem_to_private_key(f.read())


def load_public_key(username, keys_dir="keys"):
    path = os.path.join(keys_dir, f"{username}_public.pem")
    with open(path, "r") as f:
        return pem_to_public_key(f.read())


# ═════════════════════════════════════════════════════════════════════════════
# 2. AES-256-CBC ENCRYPTION / DECRYPTION
# ═════════════════════════════════════════════════════════════════════════════

def _pad(data: bytes, block_size=16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """PKCS#7 unpadding."""
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt(plaintext: str, aes_key: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-CBC encrypt a string.
    Returns (iv, ciphertext) both as raw bytes.
    """
    iv         = os.urandom(16)
    cipher     = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor  = cipher.encryptor()
    padded     = _pad(plaintext.encode("utf-8"))
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, aes_key: bytes) -> str:
    """AES-256-CBC decrypt. Returns plaintext string."""
    cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(padded).decode("utf-8")


# ═════════════════════════════════════════════════════════════════════════════
# 3. RSA-OAEP KEY WRAPPING / UNWRAPPING
# ═════════════════════════════════════════════════════════════════════════════

def rsa_wrap_key(aes_key: bytes, receiver_public_key) -> bytes:
    """
    Encrypt (wrap) the AES key using the receiver's RSA public key (OAEP-SHA256).
    Returns encrypted key bytes.
    """
    return receiver_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_unwrap_key(encrypted_key: bytes, receiver_private_key) -> bytes:
    """
    Decrypt (unwrap) the AES key using the receiver's RSA private key.
    Returns the original AES key bytes.
    """
    return receiver_private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ═════════════════════════════════════════════════════════════════════════════
# 4. XML CANONICALIZATION (C14N)
# ═════════════════════════════════════════════════════════════════════════════

def canonicalize(element) -> bytes:
    """
    Apply W3C Exclusive Canonical XML (exc-C14N) to an lxml element.
    Serializes the element to a self-contained byte string first so the
    canonical form is identical regardless of the surrounding tree context
    (important: signing and verifying must produce the exact same bytes).
    """
    import io
    # Step 1: Serialize element to raw bytes (strip parent namespace context)
    raw = etree.tostring(element, encoding="unicode")
    # Step 2: Re-parse as a fresh standalone document
    standalone = etree.fromstring(raw.encode("utf-8"))
    # Step 3: Apply exclusive C14N on the standalone element
    buf = io.BytesIO()
    etree.ElementTree(standalone).write_c14n(buf, exclusive=True, with_comments=False)
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
# 5. BUILD SECURE XML MESSAGE  (Encrypt + Sign)
# ═════════════════════════════════════════════════════════════════════════════

def build_secure_message(
    plaintext_msg: str,
    sender_username: str,
    sender_private_key,
    receiver_public_key
) -> str:
    """
    Builds a fully encrypted and signed XML message.

    Steps:
      1. Generate random AES-256 key
      2. AES-encrypt the plaintext → (iv, ciphertext)
      3. RSA-OAEP wrap the AES key with receiver's public key
      4. Build xenc:EncryptedData XML element
      5. C14N-canonicalize the EncryptedData element
      6. RSA-SHA256 sign the C14N bytes
      7. Build ds:Signature element
      8. Wrap both in <SecureMessage>

    Returns the XML string to be sent over SOAP.
    """

    # Step 1: Random AES key
    aes_key = os.urandom(32)  # 256-bit

    # Step 2: AES encrypt
    iv, ciphertext = aes_encrypt(plaintext_msg, aes_key)

    # Step 3: RSA wrap AES key
    encrypted_aes_key = rsa_wrap_key(aes_key, receiver_public_key)

    # Step 4: Build xenc:EncryptedData
    enc_data = etree.Element("{%s}EncryptedData" % NS_XENC, nsmap=NSMAP)
    enc_data.set("Type", "http://www.w3.org/2001/04/xmlenc#Element")

    # EncryptionMethod
    enc_method = etree.SubElement(enc_data, "{%s}EncryptionMethod" % NS_XENC)
    enc_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes256-cbc")

    # KeyInfo > EncryptedKey > EncryptionMethod + CipherData
    key_info = etree.SubElement(enc_data, "{%s}KeyInfo" % NS_DS)
    enc_key  = etree.SubElement(key_info, "{%s}EncryptedKey" % NS_XENC)

    ek_enc_method = etree.SubElement(enc_key, "{%s}EncryptionMethod" % NS_XENC)
    ek_enc_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")

    ek_cipher_data  = etree.SubElement(enc_key, "{%s}CipherData" % NS_XENC)
    ek_cipher_value = etree.SubElement(ek_cipher_data, "{%s}CipherValue" % NS_XENC)
    ek_cipher_value.text = base64.b64encode(encrypted_aes_key).decode("utf-8")

    # CipherData: IV prepended to ciphertext (standard practice)
    cipher_data  = etree.SubElement(enc_data, "{%s}CipherData" % NS_XENC)
    cipher_value = etree.SubElement(cipher_data, "{%s}CipherValue" % NS_XENC)
    cipher_value.text = base64.b64encode(iv + ciphertext).decode("utf-8")

    # Set Id BEFORE canonicalization so it matches what the verifier sees
    enc_data.set("Id", "EncryptedData")

    # Step 5: Canonicalize the EncryptedData for signing
    c14n_bytes = canonicalize(enc_data)

    # Step 6: SHA256 digest + RSA sign
    digest        = hashlib.sha256(c14n_bytes).digest()
    sig_bytes     = sender_private_key.sign(
        c14n_bytes,
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64   = base64.b64encode(sig_bytes).decode("utf-8")
    digest_b64 = base64.b64encode(digest).decode("utf-8")

    # Step 7: Build ds:Signature element
    signature = etree.Element("{%s}Signature" % NS_DS, nsmap=NSMAP)

    signed_info = etree.SubElement(signature, "{%s}SignedInfo" % NS_DS)

    c14n_method = etree.SubElement(signed_info, "{%s}CanonicalizationMethod" % NS_DS)
    c14n_method.set("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")

    sig_method = etree.SubElement(signed_info, "{%s}SignatureMethod" % NS_DS)
    sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    reference = etree.SubElement(signed_info, "{%s}Reference" % NS_DS)
    reference.set("URI", "#EncryptedData")

    digest_method = etree.SubElement(reference, "{%s}DigestMethod" % NS_DS)
    digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

    digest_value = etree.SubElement(reference, "{%s}DigestValue" % NS_DS)
    digest_value.text = digest_b64

    sig_value = etree.SubElement(signature, "{%s}SignatureValue" % NS_DS)
    sig_value.text = sig_b64

    sig_key_info = etree.SubElement(signature, "{%s}KeyInfo" % NS_DS)
    key_name     = etree.SubElement(sig_key_info, "{%s}KeyName" % NS_DS)
    key_name.text = sender_username

    # Step 8: Wrap in <SecureMessage>
    root = etree.Element("SecureMessage", nsmap=NSMAP)
    root.set("sender", sender_username)
    root.append(enc_data)   # Id already set above
    root.append(signature)

    return etree.tostring(root, encoding="unicode")


# ═════════════════════════════════════════════════════════════════════════════
# 6. PARSE & DECRYPT SECURE XML MESSAGE  (Verify Signature + Decrypt)
# ═════════════════════════════════════════════════════════════════════════════

def parse_secure_message(
    xml_str: str,
    receiver_private_key,
    sender_public_key
) -> dict:
    """
    Parse, verify, and decrypt a SecureMessage XML string.

    Returns a dict:
      { "sender": str, "plaintext": str, "signature_valid": bool }

    Raises ValueError if signature is invalid or decryption fails.
    """
    root = etree.fromstring(xml_str.encode("utf-8"))

    sender = root.get("sender", "unknown")

    # ── Locate EncryptedData ─────────────────────────────────────────────────
    enc_data = root.find("{%s}EncryptedData" % NS_XENC)
    if enc_data is None:
        raise ValueError("No xenc:EncryptedData found in message")

    # ── Locate Signature ─────────────────────────────────────────────────────
    signature = root.find("{%s}Signature" % NS_DS)
    if signature is None:
        raise ValueError("No ds:Signature found in message")

    # ── Step 1: C14N the EncryptedData (same way as during signing) ──────────
    c14n_bytes = canonicalize(enc_data)

    # ── Step 2: Verify digest matches ───────────────────────────────────────
    signed_info  = signature.find("{%s}SignedInfo" % NS_DS)
    reference    = signed_info.find("{%s}Reference" % NS_DS)
    digest_value = reference.find("{%s}DigestValue" % NS_DS).text
    expected_digest = base64.b64decode(digest_value)
    actual_digest   = hashlib.sha256(c14n_bytes).digest()

    if actual_digest != expected_digest:
        raise ValueError("Digest mismatch — XML may have been tampered with!")

    # ── Step 3: Verify RSA signature ─────────────────────────────────────────
    sig_value_el = signature.find("{%s}SignatureValue" % NS_DS)
    sig_bytes    = base64.b64decode(sig_value_el.text)

    try:
        sender_public_key.verify(
            sig_bytes,
            c14n_bytes,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_valid = True
    except Exception:
        raise ValueError("Signature verification FAILED — message is not authentic!")

    # ── Step 4: Extract and unwrap the AES key ───────────────────────────────
    enc_key_el       = enc_data.find(".//{%s}EncryptedKey" % NS_XENC)
    ek_cipher_value  = enc_key_el.find("{%s}CipherData/{%s}CipherValue" % (NS_XENC, NS_XENC)).text
    encrypted_aes_key = base64.b64decode(ek_cipher_value)
    aes_key           = rsa_unwrap_key(encrypted_aes_key, receiver_private_key)

    # ── Step 5: Extract IV + ciphertext and decrypt ───────────────────────────
    cipher_value_el = enc_data.find("{%s}CipherData/{%s}CipherValue" % (NS_XENC, NS_XENC))
    raw             = base64.b64decode(cipher_value_el.text)
    iv, ciphertext  = raw[:16], raw[16:]
    plaintext       = aes_decrypt(iv, ciphertext, aes_key)

    return {
        "sender":           sender,
        "plaintext":        plaintext,
        "signature_valid":  signature_valid
    }
