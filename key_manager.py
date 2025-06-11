# key_manager.py
# Private Key üretme, şifreleme ve dosya yönetimi

from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

def create_private_key():
    """Yeni bir ECDSA private key oluştur ve döndür."""
    key = ECC.generate(curve='P-256')
    return key

def save_encrypted_key(private_key, filename, password):
    """Private Key’i AES-256 ile şifreleyerek dosyaya kaydet."""
    key_bytes = private_key.export_key(format='DER')
    
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Password üzerinden AES anahtarı türet
    aes_key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Padding (AES blok boyutuna tam bölünsün diye)
    pad_len = 16 - len(key_bytes) % 16
    padded_key = key_bytes + bytes([pad_len] * pad_len)
    
    ciphertext = cipher.encrypt(padded_key)

    # Dosyaya yaz → salt, iv ve ciphertext
    with open(filename, 'wb') as f:
        f.write(base64.b64encode(salt) + b'\n')
        f.write(base64.b64encode(iv) + b'\n')
        f.write(base64.b64encode(ciphertext))
    
    print(f" Private Key sifreli olarak {filename} dosyasina kaydedildi.")

def load_encrypted_key(filename, password):
    """Sifreli dosyadan Private Key i AES-256 ile cozerek oku."""
    with open(filename, 'rb') as f:
        salt = base64.b64decode(f.readline().strip())
        iv = base64.b64decode(f.readline().strip())
        ciphertext = base64.b64decode(f.read())

    # Password üzerinden AES anahtarı türet
    aes_key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_key = cipher.decrypt(ciphertext)

    # Padding’i kaldır
    pad_len = padded_key[-1]
    key_bytes = padded_key[:-pad_len]

    private_key = ECC.import_key(key_bytes)
    return private_key
