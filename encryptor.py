# encryptor.py
# AES-256 şifreleme ve çözme modülü

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

def encrypt_data(data, password, salt, iv):
    """
    Verilen data (bytes) paroladan türetilen AES anahtarı ile şifrelenir.
    data: bytes
    password: string
    salt: bytes
    iv: bytes
    """
    aes_key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Padding
    pad_len = 16 - len(data) % 16
    padded_data = data + bytes([pad_len] * pad_len)

    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

def decrypt_data(ciphertext, password, salt, iv):
    try:
        aes_key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)

        pad_len = padded_data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Gecersiz padding boyutu!")
        
        data = padded_data[:-pad_len]
        return data
    except Exception as e:
        raise ValueError(f"Veri cozme hatasi: {e}")
