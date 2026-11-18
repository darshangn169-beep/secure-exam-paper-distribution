"""
crypto_utils.py
----------------
All cryptographic operations for the Secure Exam Paper Distribution System.

Concepts implemented:
  1. AES-256 (symmetric)      -> encrypts the actual exam paper (bulk data)
  2. RSA-2048 (asymmetric)    -> encrypts the AES key (key exchange / hybrid encryption)
  3. SHA-256                  -> integrity hash of the plaintext paper
  4. RSA Digital Signature    -> signs the hash so the receiver can verify
                                 authenticity + detect tampering
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes


# ---------- RSA KEY GENERATION ----------

def generate_rsa_keypair(bits=2048):
    """Generate a new RSA key pair. Returns (private_pem, public_pem) as bytes."""
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem


# ---------- AES (SYMMETRIC) ENCRYPTION ----------

def aes_encrypt(plaintext: bytes):
    """
    Encrypt data with AES-256 in EAX mode (gives confidentiality + built-in
    integrity check via the authentication tag).
    Returns (ciphertext, key, nonce, tag)
    """
    key = get_random_bytes(32)          # AES-256 -> 32 byte key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, key, cipher.nonce, tag


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    """
    Decrypt AES-256 EAX ciphertext. Raises ValueError if the tag doesn't
    match (i.e. data was tampered with or the key/nonce is wrong).
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


# ---------- RSA (ASYMMETRIC) — used only to wrap the small AES key ----------

def rsa_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
    """Encrypt small data (the AES key) using RSA-OAEP with a public key."""
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data)


def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt data using RSA-OAEP with a private key."""
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)


# ---------- SHA-256 INTEGRITY HASH ----------

def sha256_hash(data: bytes) -> bytes:
    """Return the raw SHA-256 digest of data."""
    h = SHA256.new(data)
    return h.digest()


def sha256_hexdigest(data: bytes) -> str:
    """Return the SHA-256 hash as a hex string (for display/storage)."""
    return SHA256.new(data).hexdigest()


# ---------- DIGITAL SIGNATURE (authenticity + tamper detection) ----------

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign the SHA-256 hash of `data` using the sender's RSA private key."""
    priv_key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify a signature against data using the sender's RSA public key."""
    pub_key = RSA.import_key(public_key_pem)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
