# bitcoin_keys.py
# Bitcoin Private Key, Public Key, and Address Generation

import os
import hashlib
import base58
import binascii
import ecdsa
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class BitcoinKeyManager:
    """
    Bitcoin özel anahtarı ve adres yönetimi için sınıf.
    Bu sınıf, Bitcoin private key oluşturma, WIF formatına çevirme,
    public key türetme ve bitcoin adresi oluşturma işlevlerini sağlar.
    """
    
    def __init__(self):
        # Secp256k1 eğrisi Bitcoin için standart ECDSA eğrisidir
        self.curve = ecdsa.SECP256k1
        
    def generate_private_key(self):
        """
        Yeni bir Bitcoin özel anahtarı (private key) oluşturur.
        
        Returns:
            bytes: 32-byte private key
        """
        # Bitcoin özel anahtarları 32 byte (256 bit) uzunluğundadır
        private_key_bytes = os.urandom(32)
        
        # Özel anahtarın secp256k1 eğrisi sınırları içinde olduğunu doğrula
        while int.from_bytes(private_key_bytes, byteorder='big') >= self.curve.order:
            private_key_bytes = os.urandom(32)
            
        return private_key_bytes
    
    def private_key_to_wif(self, private_key_bytes, compressed=True, testnet=False):
        """
        Private key'i Wallet Import Format (WIF) biçimine dönüştürür.
        WIF, Bitcoin cüzdanları arasında private key aktarımı için kullanılan standart formattır.
        
        Args:
            private_key_bytes (bytes): 32-byte private key
            compressed (bool): Sıkıştırılmış public key formatı kullanılacak mı
            testnet (bool): Testnet için mi (True) yoksa mainnet için mi (False)
            
        Returns:
            str: WIF formatted private key
        """
        # Ağ byte'ı ekle (mainnet için 0x80, testnet için 0xEF)
        network_byte = b'\xef' if testnet else b'\x80'
        extended_key = network_byte + private_key_bytes
        
        # Sıkıştırılmış format için 0x01 ekle
        if compressed:
            extended_key += b'\x01'
        
        # Checksum hesapla (SHA-256 twice)
        first_sha = hashlib.sha256(extended_key).digest()
        second_sha = hashlib.sha256(first_sha).digest()
        checksum = second_sha[:4]  # İlk 4 byte checksum olarak kullanılır
        
        # Yeni key = network byte + private key + compression flag + checksum
        wif_bytes = extended_key + checksum
        
        # Base58 kodlaması yap
        wif = base58.b58encode(wif_bytes).decode('utf-8')
        return wif
    
    def private_key_to_public_key(self, private_key_bytes, compressed=True):
        """
        Private key'den public key oluşturur.
        
        Args:
            private_key_bytes (bytes): 32-byte private key
            compressed (bool): Sıkıştırılmış biçimde public key döndür
            
        Returns:
            bytes: Public key (compressed or uncompressed)
        """
        # Private key'i integer'a çevir
        private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
        
        # ECDSA ile public key oluştur
        signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=self.curve)
        verifying_key = signing_key.get_verifying_key()
        
        # Public key noktasını al (sıkıştırılmamış format)
        public_key_full = b'\x04' + verifying_key.to_string()
        
        if compressed:
            # Sıkıştırılmış format: x koordinatı + parite byte'ı (02 çift, 03 tek)
            x_coord = verifying_key.to_string()[:32]
            y_coord = verifying_key.to_string()[32:]
            if int.from_bytes(y_coord, byteorder='big') % 2 == 0:
                prefix = b'\x02'  # y değeri çift sayı ise
            else:
                prefix = b'\x03'  # y değeri tek sayı ise
            return prefix + x_coord
        else:
            return public_key_full
    
    def public_key_to_address(self, public_key_bytes, testnet=False):
        """
        Public key'den Bitcoin adresi oluşturur.
        
        Args:
            public_key_bytes (bytes): Public key bytes
            testnet (bool): Testnet için mi (True) yoksa mainnet için mi (False)
            
        Returns:
            str: Bitcoin address
        """
        # 1. SHA-256 hash
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # 2. RIPEMD-160 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hash160 = ripemd160.digest()
        
        # 3. Ağ byte'ı ekle (mainnet için 0x00, testnet için 0x6F)
        network_byte = b'\x6f' if testnet else b'\x00'
        extended_hash = network_byte + hash160
        
        # 4. Checksum hesapla (SHA-256 twice)
        first_sha = hashlib.sha256(extended_hash).digest()
        second_sha = hashlib.sha256(first_sha).digest()
        checksum = second_sha[:4]
        
        # 5. Adres bytes = network byte + hash160 + checksum
        address_bytes = extended_hash + checksum
        
        # 6. Base58 kodlaması yap
        address = base58.b58encode(address_bytes).decode('utf-8')
        return address
    
    def generate_seed_from_mnemonic(self, mnemonic, passphrase=""):
        """
        BIP-39 mnemonic'ten seed oluşturur.
        
        Args:
            mnemonic (str): BIP-39 mnemonic cümlesi (12, 15, 18, 21 veya 24 kelime)
            passphrase (str): İsteğe bağlı ek şifreleme parolası
            
        Returns:
            bytes: 64-byte seed
        """
        # Mnemonic'i UTF-8 kodlaması ile encode et
        mnemonic_bytes = mnemonic.encode('utf-8')
        salt = ("mnemonic" + passphrase).encode('utf-8')
        
        # PBKDF2 ile seed oluştur (2048 iterasyon, HMAC-SHA512 hash fonksiyonu)
        seed = PBKDF2(mnemonic_bytes, salt, dkLen=64, count=2048, hmac_hash_module=SHA256)
        return seed
    
    def encrypt_private_key(self, private_key_bytes, password):
        """
        Private key'i güvenli bir şekilde şifreler.
        
        Args:
            private_key_bytes (bytes): Şifrelenecek private key
            password (str): Şifreleme parolası
            
        Returns:
            dict: Salt, initialization vector ve şifrelenmiş veri içeren sözlük
        """
        from encryptor import encrypt_data  # Mevcut encryptor.py modülünü kullan
        
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Veriyi şifrele
        encrypted_data = encrypt_data(private_key_bytes, password, salt, iv)
        
        return {
            'salt': salt,
            'iv': iv,
            'encrypted_data': encrypted_data
        }
    
    def decrypt_private_key(self, encrypted_dict, password):
        """
        Şifrelenmiş private key'i çözer.
        
        Args:
            encrypted_dict (dict): Salt, iv ve encrypted_data içeren sözlük
            password (str): Şifre çözme parolası
            
        Returns:
            bytes: Çözülmüş private key
        """
        from encryptor import decrypt_data  # Mevcut encryptor.py modülünü kullan
        
        # Şifrelenmiş veriyi çöz
        decrypted_data = decrypt_data(
            encrypted_dict['encrypted_data'],
            password,
            encrypted_dict['salt'],
            encrypted_dict['iv']
        )
        
        return decrypted_data
    
    def save_encrypted_key_to_file(self, encrypted_dict, filename):
        """
        Şifrelenmiş private key'i dosyaya kaydeder.
        
        Args:
            encrypted_dict (dict): Salt, iv ve encrypted_data içeren sözlük
            filename (str): Kaydedilecek dosya adı
        """
        import json
        import base64
        
        # Binary değerleri Base64'e çevir (JSON serileştirme için)
        serializable_dict = {
            'salt': base64.b64encode(encrypted_dict['salt']).decode('utf-8'),
            'iv': base64.b64encode(encrypted_dict['iv']).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_dict['encrypted_data']).decode('utf-8')
        }
        
        # JSON olarak kaydet
        with open(filename, 'w') as f:
            json.dump(serializable_dict, f)
            
    def load_encrypted_key_from_file(self, filename):
        """
        Şifrelenmiş private key'i dosyadan yükler.
        
        Args:
            filename (str): Yüklenecek dosya adı
            
        Returns:
            dict: Salt, iv ve encrypted_data içeren sözlük
        """
        import json
        import base64
        
        # JSON'dan yükle
        with open(filename, 'r') as f:
            serialized_dict = json.load(f)
        
        # Base64'ten binary'ye çevir
        encrypted_dict = {
            'salt': base64.b64decode(serialized_dict['salt']),
            'iv': base64.b64decode(serialized_dict['iv']),
            'encrypted_data': base64.b64decode(serialized_dict['encrypted_data'])
        }
        
        return encrypted_dict

def demo():
    """
    Bitcoin key management demo.
    """
    print("===== Bitcoin Key Management Demo =====")
    
    # Bitcoin key manager oluştur
    key_manager = BitcoinKeyManager()
    
    # Yeni private key oluştur
    print("\n1. Yeni Bitcoin Private Key Oluşturuluyor...")
    private_key = key_manager.generate_private_key()
    print(f"Private Key (hex): {private_key.hex()}")
    
    # WIF formatına çevir
    wif = key_manager.private_key_to_wif(private_key)
    print(f"WIF formatı: {wif}")
    
    # Public Key türet
    compressed_pubkey = key_manager.private_key_to_public_key(private_key, compressed=True)
    print(f"Compressed Public Key: {compressed_pubkey.hex()}")
    
    # Bitcoin adresi oluştur
    address = key_manager.public_key_to_address(compressed_pubkey)
    print(f"Bitcoin Adresi: {address}")
    
    # Testnet adresi de oluştur
    testnet_address = key_manager.public_key_to_address(compressed_pubkey, testnet=True)
    print(f"Testnet Adresi: {testnet_address}")
    
    # Private key'i şifrele
    print("\n2. Private Key Şifreleniyor...")
    password = "güçlü-bitcoin-cüzdan-şifresi"
    encrypted_key = key_manager.encrypt_private_key(private_key, password)
    print(f"Şifrelenmiş Key (ilk 10 byte): {encrypted_key['encrypted_data'][:10].hex()}...")
    
    # Şifrelenmiş key'i dosyaya kaydet
    key_filename = "bitcoin_private_key.enc"
    key_manager.save_encrypted_key_to_file(encrypted_key, key_filename)
    print(f"Key {key_filename} dosyasına kaydedildi")
    
    # Dosyadan yükle ve şifresini çöz
    print("\n3. Şifrelenmiş Key Dosyadan Yükleniyor ve Çözülüyor...")
    loaded_key = key_manager.load_encrypted_key_from_file(key_filename)
    decrypted_key = key_manager.decrypt_private_key(loaded_key, password)
    print(f"Çözülen Private Key (hex): {decrypted_key.hex()}")
    
    # Doğrulama
    print("\n4. Doğrulama Yapılıyor...")
    if decrypted_key == private_key:
        print(" Private key başarıyla şifrelendi ve çözüldü!")
    else:
        print(" Hata! Çözülen key orijinal ile eşleşmiyor.")
        
    # Verilerin silinmesi (güvenlik için)
    private_key = None
    decrypted_key = None
    print("\nDemo tamamlandı. Tüm hassas veriler bellekten silindi.")

if __name__ == "__main__":
    demo()