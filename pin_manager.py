# Enhanced pin_manager.py with salting
import hashlib
import os
import base64

PIN_HASH_FILE = "pin_hash.txt"

def set_pin(pin):
    """
    Sets a new PIN with salt and proper storage.
    """
    # Generate a random salt
    salt = os.urandom(16)
    
    # Hash the PIN with the salt
    pin_hash = hashlib.sha256(salt + pin.encode()).hexdigest()
    
    # Store both salt and hash
    with open(PIN_HASH_FILE, 'w') as f:
        f.write(base64.b64encode(salt).decode() + '\n')
        f.write(pin_hash)
    
    print(" PIN kaydedildi.")

def verify_pin(input_pin):
    try:
        if not os.path.exists(PIN_HASH_FILE):
            print(" PIN dosyasi bulunamadi. Önce PIN olusturmalisiniz.")
            return False

        with open(PIN_HASH_FILE, 'r') as f:
            stored_salt_b64 = f.readline().strip()
            stored_pin_hash = f.readline().strip()
        
        # Decode the salt
        salt = base64.b64decode(stored_salt_b64)
        
        # Hash the input PIN with the stored salt
        input_pin_hash = hashlib.sha256(salt + input_pin.encode()).hexdigest()
        
        return input_pin_hash == stored_pin_hash
    except Exception as e:
        print(f" PIN dogrulama hatasi: {e}")
        return False