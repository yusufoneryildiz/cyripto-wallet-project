# bitcoin_transactions.py
# Bitcoin işlemi oluşturma, imzalama ve doğrulama işlemleri

import hashlib
import struct
import binascii
import ecdsa
from io import BytesIO
from bitcoin_keys import BitcoinKeyManager

class BitcoinTransaction:
    """
    Bitcoin işlemi sınıfı.
    Bu sınıf basitleştirilmiş Bitcoin işlemleri oluşturmak, imzalamak 
    ve doğrulamak için kullanılır.
    """
    
    def __init__(self):
        self.version = 1
        self.inputs = []  # İşlem girdileri (UTXO'lar)
        self.outputs = []  # İşlem çıktıları
        self.locktime = 0
        
    def add_input(self, txid, vout, script_sig=b'', sequence=0xffffffff):
        """
        İşleme bir girdi ekler.
        
        Args:
            txid (str): Önceki işlem ID'si (hex string)
            vout (int): Önceki işlemdeki çıktı indeksi
            script_sig (bytes): İmza scripti (genellikle imzalamadan önce boş)
            sequence (int): Sequence numarası
        """
        # txid'yi little-endian byte array'e çevir
        txid_bytes = bytes.fromhex(txid)[::-1]  # Reverse for little-endian
        
        self.inputs.append({
            'txid': txid_bytes,
            'vout': vout,
            'script_sig': script_sig,
            'sequence': sequence
        })
        
    def add_output(self, value, script_pubkey):
        """
        İşleme bir çıktı ekler.
        
        Args:
            value (int): Satoshi cinsinden gönderilecek miktar
            script_pubkey (bytes): Output script'i (genellikle alıcı adresi)
        """
        self.outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    
    def add_p2pkh_output(self, value, bitcoin_address):
        """
        Pay-to-Public-Key-Hash (P2PKH) çıktısı ekler.
        
        Args:
            value (int): Satoshi cinsinden gönderilecek miktar
            bitcoin_address (str): Alıcı bitcoin adresi
        """
        from base58 import b58decode
        
        # Bitcoin adresini decode et
        address_bytes = b58decode(bitcoin_address)
        
        # Network byte ve checksum'ı çıkar
        hash160 = address_bytes[1:-4]
        
        # P2PKH scriptPubKey: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
        script_pubkey = b'\x76\xa9\x14' + hash160 + b'\x88\xac'
        
        self.add_output(value, script_pubkey)
        
    def serialize_for_signing(self, input_index, script_pubkey, sighash_type=1):
        """
        Belirli bir girdiyi imzalamak için işlemi serileştirir.
        
        Args:
            input_index (int): İmzalanacak girdinin indeksi
            script_pubkey (bytes): Harcanacak UTXO'nun scripti
            sighash_type (int): İmza tipi (genellikle SIGHASH_ALL=1)
            
        Returns:
            bytes: İmza için hazırlanmış serileştirme
        """
        tx_copy = BitcoinTransaction()
        tx_copy.version = self.version
        tx_copy.locktime = self.locktime
        
        # Tüm girdileri kopyala
        for i, tx_in in enumerate(self.inputs):
            script = script_pubkey if i == input_index else b''
            tx_copy.add_input(
                txid=tx_in['txid'][::-1].hex(),  # Reverse back for add_input
                vout=tx_in['vout'],
                script_sig=script,
                sequence=tx_in['sequence']
            )
        
        # Tüm çıktıları kopyala
        for tx_out in self.outputs:
            tx_copy.add_output(tx_out['value'], tx_out['script_pubkey'])
            
        # Serileştir
        tx_serialized = tx_copy.serialize() + struct.pack("<I", sighash_type)
        return tx_serialized
    
    def sign_input(self, input_index, private_key_bytes, script_pubkey, sighash_type=1):
        """
        Belirli bir girdiyi imzalar.
        
        Args:
            input_index (int): İmzalanacak girdinin indeksi
            private_key_bytes (bytes): İmza için kullanılacak private key
            script_pubkey (bytes): Harcanacak UTXO'nun scripti
            sighash_type (int): İmza tipi (genellikle SIGHASH_ALL=1)
            
        Returns:
            bytes: DER formatında imza + sighash byte
        """
        # İmza için işlemi serileştir
        tx_serialized = self.serialize_for_signing(input_index, script_pubkey, sighash_type)
        
        # Double SHA-256 hash
        tx_hash = hashlib.sha256(hashlib.sha256(tx_serialized).digest()).digest()
        
        # ECDSA imzalama - Bitcoin'de kullanılan secp256k1 eğrisi ile
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        signature = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der)
        
        # İmzaya sighash_type ekle
        signature_with_hashtype = signature + bytes([sighash_type])
        
        return signature_with_hashtype
    
    def create_p2pkh_signature_script(self, signature, public_key_bytes):
        """
        P2PKH için tam bir ScriptSig oluşturur.
        
        Args:
            signature (bytes): İmza (DER formatı + sighash_type)
            public_key_bytes (bytes): Sıkıştırılmış veya sıkıştırılmamış public key
            
        Returns:
            bytes: ScriptSig
        """
        # ScriptSig: <signature> <pubkey>
        script_sig = bytes([len(signature)]) + signature + bytes([len(public_key_bytes)]) + public_key_bytes
        return script_sig
    
    def sign_p2pkh_input(self, input_index, private_key_bytes, script_pubkey):
        """
        P2PKH girdisini imzalamak için yardımcı metod.
        
        Args:
            input_index (int): İmzalanacak girdinin indeksi
            private_key_bytes (bytes): İmza için kullanılacak private key
            script_pubkey (bytes): Harcanacak UTXO'nun scripti
        """
        # Private key'den public key oluştur
        key_manager = BitcoinKeyManager()
        public_key = key_manager.private_key_to_public_key(private_key_bytes, compressed=True)
        
        # İmza oluştur
        signature = self.sign_input(input_index, private_key_bytes, script_pubkey)
        
        # ScriptSig oluştur ve girdiye ekle
        script_sig = self.create_p2pkh_signature_script(signature, public_key)
        self.inputs[input_index]['script_sig'] = script_sig
        
    def serialize(self):
        """
        İşlemi Bitcoin protokolüne uygun şekilde serileştirir.
        
        Returns:
            bytes: Serileştirilmiş işlem
        """
        # BytesIO buffer kullanarak işlemi oluşturacağız
        buffer = BytesIO()
        
        # Version (4 bytes, little-endian)
        buffer.write(struct.pack("<I", self.version))
        
        # Input count (VarInt)
        buffer.write(self._encode_varint(len(self.inputs)))
        
        # Inputs
        for tx_in in self.inputs:
            buffer.write(tx_in['txid'])  # TXID (32 bytes, already little-endian)
            buffer.write(struct.pack("<I", tx_in['vout']))  # vout (4 bytes, little-endian)
            
            # ScriptSig (VarInt + script)
            buffer.write(self._encode_varint(len(tx_in['script_sig'])))
            buffer.write(tx_in['script_sig'])
            
            # Sequence (4 bytes, little-endian)
            buffer.write(struct.pack("<I", tx_in['sequence']))
            
        # Output count (VarInt)
        buffer.write(self._encode_varint(len(self.outputs)))
        
        # Outputs
        for tx_out in self.outputs:
            # Value (8 bytes, little-endian)
            buffer.write(struct.pack("<Q", tx_out['value']))
            
            # ScriptPubKey (VarInt + script)
            buffer.write(self._encode_varint(len(tx_out['script_pubkey'])))
            buffer.write(tx_out['script_pubkey'])
            
        # Locktime (4 bytes, little-endian)
        buffer.write(struct.pack("<I", self.locktime))
        
        # Serileştirilmiş işlemi döndür
        return buffer.getvalue()
    
    def get_txid(self):
        """
        İşlemin TXID'sini hesaplar (double SHA-256 hash).
        
        Returns:
            str: TXID (hex string, little-endian)
        """
        # İşlemi serileştir
        tx_serialized = self.serialize()
        
        # Double SHA-256 hash
        tx_hash = hashlib.sha256(hashlib.sha256(tx_serialized).digest()).digest()
        
        # Hash'i little-endian hex string'e çevir
        return tx_hash[::-1].hex()  # Reverse for big-endian display
    
    def _encode_varint(self, integer):
        """
        Bir tam sayıyı Bitcoin VarInt formatına dönüştürür.
        
        Args:
            integer (int): Kodlanacak tam sayı
            
        Returns:
            bytes: VarInt formatında kodlanmış değer
        """
        if integer < 0xfd:
            return bytes([integer])
        elif integer <= 0xffff:
            return b'\xfd' + struct.pack("<H", integer)
        elif integer <= 0xffffffff:
            return b'\xfe' + struct.pack("<I", integer)
        else:
            return b'\xff' + struct.pack("<Q", integer)
    
    @staticmethod
    def create_p2pkh_script_pubkey(bitcoin_address):
        """
        Bitcoin adresinden P2PKH scriptPubKey oluşturur.
        
        Args:
            bitcoin_address (str): Bitcoin adresi
            
        Returns:
            bytes: P2PKH scriptPubKey
        """
        from base58 import b58decode
        
        # Bitcoin adresini decode et
        address_bytes = b58decode(bitcoin_address)
        
        # Network byte ve checksum'ı çıkar
        hash160 = address_bytes[1:-4]
        
        # P2PKH scriptPubKey: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
        script_pubkey = b'\x76\xa9\x14' + hash160 + b'\x88\xac'
        
        return script_pubkey
    
    @staticmethod
    def decode_script_pubkey(script_pubkey):
        """
        scriptPubKey'i insan tarafından okunabilir formata dönüştürür.
        
        Args:
            script_pubkey (bytes): scriptPubKey
            
        Returns:
            str: İnsan tarafından okunabilir script
        """
        if len(script_pubkey) == 25 and script_pubkey[0] == 0x76 and script_pubkey[1] == 0xa9 and script_pubkey[2] == 0x14 and script_pubkey[23] == 0x88 and script_pubkey[24] == 0xac:
            # Bu bir P2PKH scriptidir
            hash160 = script_pubkey[3:23].hex()
            return f"OP_DUP OP_HASH160 {hash160} OP_EQUALVERIFY OP_CHECKSIG"
        else:
            # Tam çözümleme gerçekleştirmiyoruz, hex olarak döndür
            return script_pubkey.hex()

def create_simple_transaction(from_txid, from_vout, from_private_key, to_address, amount_satoshis, fee_satoshis, change_address=None):
    """
    Basit bir Bitcoin işlemi oluşturup imzalar.
    
    Args:
        from_txid (str): Harcanacak UTXO'nun işlem ID'si
        from_vout (int): Harcanacak UTXO'nun çıktı indeksi
        from_private_key (bytes): Harcama için kullanılacak private key
        to_address (str): Alıcı Bitcoin adresi
        amount_satoshis (int): Gönderilecek miktar (satoshi cinsinden)
        fee_satoshis (int): İşlem ücreti (satoshi cinsinden)
        change_address (str, optional): Para üstü adresi. None ise gönderen adres kullanılır.
        
    Returns:
        BitcoinTransaction: İmzalanmış işlem
    """
    key_manager = BitcoinKeyManager()
    
    # Public key ve adres türet
    public_key = key_manager.private_key_to_public_key(from_private_key, compressed=True)
    from_address = key_manager.public_key_to_address(public_key)
    
    # Para üstü adresi belirtilmemişse, gönderen adresi kullan
    if change_address is None:
        change_address = from_address
    
    # Toplam UTXO değeri (örnek - gerçekte bu değer blockchain'den sorgulanmalıdır)
    # Bu örnek için, gönderilecek miktar + ücret + para üstü toplamı kadar UTXO değerimiz olduğunu varsayıyoruz
    utxo_value = amount_satoshis + fee_satoshis
    
    # İşlem oluştur
    tx = BitcoinTransaction()
    
    # Girdi ekle
    tx.add_input(from_txid, from_vout)
    
    # Çıktıları ekle
    tx.add_p2pkh_output(amount_satoshis, to_address)
    
    # Para üstü varsa ekle
    change_amount = utxo_value - amount_satoshis - fee_satoshis
    if change_amount > 0:
        tx.add_p2pk