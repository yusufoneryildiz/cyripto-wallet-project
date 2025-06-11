# utils.py
# Yardımcı fonksiyonlar

import hashlib

def hash_password(password):
    """
    Verilen string parolayı SHA-256 ile hashleyip döndürür.
    """
    return hashlib.sha256(password.encode()).hexdigest()
