# demo_bitcoin.py
from bitcoin_keys import BitcoinKeyManager
from bitcoin_transactions import BitcoinTransaction, create_simple_transaction

def demo_bitcoin_key_generation():
    print(" Bitcoin Anahtar ve Adres Olusturma")
    manager = BitcoinKeyManager()
    
    private_key = manager.generate_private_key()
    print(f"Private Key: {private_key.hex()}")

    wif = manager.private_key_to_wif(private_key)
    print(f"WIF formati: {wif}")

    public_key = manager.private_key_to_public_key(private_key)
    address = manager.public_key_to_address(public_key)
    print(f"Bitcoin Adresi: {address}")

def demo_transaction_signing():
    print("\n Bitcoin İşlemi Oluşturma ve İmzalama")
    manager = BitcoinKeyManager()
    private_key = manager.generate_private_key()
    public_key = manager.private_key_to_public_key(private_key)
    from_address = manager.public_key_to_address(public_key)

    # Gerçek blockchain'e bağlanmadan demo txid ve çıktı verisi kullan
    dummy_txid = "e3c0f0f1e1d0c0b0a09182736251413120191817161514131211100908070605"
    dummy_vout = 0
    to_address = "mwJnN24Qmiw7dUbtfX1UbZXTW4St1iqW1R"  # Testnet adres
    amount = 10000
    fee = 500

    tx = create_simple_transaction(
        from_txid=dummy_txid,
        from_vout=dummy_vout,
        from_private_key=private_key,
        to_address=to_address,
        amount_satoshis=amount,
        fee_satoshis=fee
    )

    print(f"TXID: {tx.get_txid()}")
    print(f"Raw Transaction: {tx.serialize().hex()}")

if __name__ == "__main__":
    demo_bitcoin_key_generation()
    demo_transaction_signing()
