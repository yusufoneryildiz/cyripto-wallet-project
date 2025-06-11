# signer.py
# Private Key ile işlem imzalama ve doğrulama modülü

from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def sign_transaction(transaction_data, private_key):
    """
    Verilen işlem verisini SHA-256 ile hashle ve private key ile imzala.
    
    transaction_data: bytes (örn. b"para transferi")
    private_key: Crypto.PublicKey.ECC nesnesi
    """
    h = SHA256.new(transaction_data)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

def verify_transaction(transaction_data, signature, public_key):
    h = SHA256.new(transaction_data)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        print(" İmza dogrulama basarisiz!")
        return False

