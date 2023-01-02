import hashlib

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey

def ed448_sign(
    client_private_key: Ed448PrivateKey,
    message: bytes
    ) -> bytes:
    '''
    ed448_sign(client private key, message to sign) -> signature

    Signs the message with the given private key

    :param client_private_key Ed448PrivateKey: Private key
    :param message bytes: Message to sign
    :returns bytes: The signature
    '''

    signature = client_private_key.sign(message)
    return signature

def ed448_verify(
    peer_public_key: Ed448PublicKey,
    message: bytes,
    signature: bytes
    ) -> bool:
    '''
    ed448_verify(peer public key, message, signature to verify) -> status

    Verifies the signature using the given public key

    :param peer_public_key Ed448PublicKey: Public key
    :param message bytes: Message to verify
    :param signature bytes: Signature to verify
    :returns bool: True if the signature is correct, False if not
    '''

    try:
        peer_public_key.verify(signature, message)

        return True
    except Exception:
        return False

def x448_key_exchange(
    client_private_key: X448PrivateKey,
    peer_public_key: X448PublicKey,
    key_length: int = 32,
    salt: bytes | None = None
    ) -> bytes:
    '''
    x448_key_exchange(client private key, peer public key, key length, salt) -> derived key

    Derives a key based off the shared key

    :param client_private_key X448PrivateKey: Private key
    :param peer_public_key X448PublicKey: Public key
    :param key_length int: Length of the derived key
    :param salt bytes or None: Salt to use when deriving the key
    :returns bytes: Derived key
    '''

    shared_key = client_private_key.exchange(
        peer_public_key
    )

    if not salt:
        salt = get_random_bytes(128) # collisions? fuck em ;P

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=None,
    ).derive(shared_key)

    return derived_key

def make_ed448_keys(
    as_pem: bool = True
    ) -> tuple[bytes, bytes] | tuple[Ed448PrivateKey, Ed448PublicKey]:
    '''
    make_ed448_keys(return in PEM format) -> private key, public key OR private key pem, public key pem

    Generates a Ed448 keypair, and returns the keys
    or the keys stored as PEM files

    :param as_pem bool: Return the keys in the PEM format
    :returns tuple[bytes, bytes] or tuple[Ed448PrivateKey, Ed448PublicKey]: The keys
    '''

    private_key = Ed448PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if as_pem:
        return private_key_pem, public_key_pem

    return private_key, public_key

def make_x448_keys(
    as_pem: bool = True
    ) -> tuple[bytes, bytes] | tuple[X448PrivateKey, X448PublicKey]:
    '''
    make_x448_keys(return in PEM format) -> private key, public key OR private key pem, public key pem

    Generates a X448 keypair, and returns the keys
    or the keys stored as PEM files

    :param as_pem bool: Return the keys in the PEM format
    :returns tuple[bytes, bytes] or tuple[X448PrivateKey, X448PublicKey]: The keys
    '''

    private_key = X448PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if as_pem:
        return private_key_pem, public_key_pem

    return private_key, public_key

def xchacha_encrypt(
    plaintext: bytes,
    key: bytes | None = None,
    nonce: bytes | None = None
    ) -> tuple[bytes, bytes, bytes]:
    '''
    xchacha_encrypt(plaintext, key, nonce) -> noncer, ciphertext, tag

    Encrypts the plaintext using XChaCha20Poly1305
    using the given key and nonce. If they are set to None, random bytes
    are chosen instead

    :param plaintext bytes: Plaintext that should be encrypted
    :param key bytes or None: Key to use, leave empty to create a random one
    :param nonce bytes or None: Nonce to use, leave empty to create a random one
    :returns tuple[bytes, bytes, bytes]: The nonce, ciphertext and tag
    '''

    if not key:
        key = get_random_bytes(32)
    
    if not nonce:
        nonce = get_random_bytes(24)

    cipher = ChaCha20_Poly1305.new(
        key=key, 
        nonce=nonce
    )

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return nonce, ciphertext, tag

def xchacha_decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    ) -> bytes | None:
    '''
    xchacha_decrypt(ciphertext, key, nonce, tag) -> cleartext or None

    Decrypts the ciphertext with the corresponding header,
    key, nonce and mac tag.

    :param ciphertext bytes: Ciphertext to decrypt
    :param key bytes: 32 bytes long key
    :param nonce bytes: 24 bytes long nonce
    :param tag bytes: 16 bytes long mac tag
    :returns bytes or None: Plaintext in bytes, else None if any errors occurred
    '''

    try:

        cipher = ChaCha20_Poly1305.new(
            key=key,
            nonce=nonce
        )

        plaintext = cipher.decrypt_and_verify(
            ciphertext=ciphertext,
            received_mac_tag=tag
        )

    except Exception as exc:
        print(exc)
        plaintext = None

    return plaintext

def do_double_hash(raw: bytes) -> tuple[str, str]:
    '''
    do_double_hash(raw bytes) -> sha256 hash, sha512 hash

    Hashes `raw` using SHA256 and 512
    and returns the hashes in a tuple

    :param raw bytes: Raw bytes to hash
    :returns tuple[str, str]: The hashes
    '''

    h1 = hashlib.sha256(raw).hexdigest()
    h2 = hashlib.sha512(raw).hexdigest()

    return h1, h2