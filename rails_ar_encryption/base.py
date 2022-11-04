from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Protocol.KDF import PBKDF2


def encrypt(clear_text, key, deterministic=False):
    """
    Encrypt message just like it's done on Rails side, see:
    https://github.com/rails/rails/blob/main/activerecord/lib/active_record/encryption/cipher/aes256_gcm.rb
    """

    iv = _generate_iv(deterministic, key, clear_text)
    cipher = AES.new(key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(clear_text.encode())

    headers = {
        "iv": b64encode(iv).decode(),
        "at": b64encode(tag).decode()
        }

    message = {
        "p": b64encode(ciphertext).decode(),
        "h": headers
        }

    return message


def decrypt(message, key):
    """
    Decrypt message just like it's done on Rails side, see:
    https://github.com/rails/rails/blob/main/activerecord/lib/active_record/encryption/cipher/aes256_gcm.rb
    """
    headers = message["h"]

    ciphertext = b64decode(message["p"].encode())
    iv = b64decode(headers["iv"].encode())
    tag = b64decode(headers["at"].encode())

    cipher = AES.new(key, AES.MODE_GCM, iv)

    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def derive_key(password, salt, deterministic=False):
    """
    Derive the key just like it's done on Rails side, see:
    https://github.com/rails/rails/blob/main/activesupport/lib/active_support/key_generator.rb#L39
    """
    # if deterministic:
    #     return PBKDF2(password, salt, 32, count=2**16, hmac_hash_module=SHA256)
    # else:
    #     return PBKDF2(password, salt, 32, count=2**16, hmac_hash_module=SHA1)

    # Use rails default key generator hash digest class SHA1
    # https://github.com/rails/rails/blob/main/activesupport/lib/active_support/key_generator.rb#L22
    return PBKDF2(password, salt, 32, count=2**16, hmac_hash_module=SHA1)


def _generate_iv(deterministic, key, clear_text):

    """
    Generate IV just like it's done on Rails side, see:
    https://github.com/rails/rails/blob/main/activerecord/lib/active_record/encryption/cipher/aes256_gcm.rb
    """
    if deterministic:
        return HMAC.new(key, clear_text.encode(), digestmod=SHA256).digest()[:12]
    else:
        return get_random_bytes(12)
