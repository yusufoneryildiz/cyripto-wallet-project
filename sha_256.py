import struct

# Sabitler
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

INITIAL_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Yardımcı döndürme ve shift fonksiyonları
def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def right_shift(x, n):
    return (x >> n)

def to_bytes(n, length, endianess='big'):
    return n.to_bytes(length, endianess)

def to_hex(byte_array):
    return ''.join([f'{b:02x}' for b in byte_array])

class SHA256:
    def __init__(self):
        self._h = INITIAL_HASH[:]
        self._unprocessed = b''
        self._message_byte_length = 0

    def update(self, arg):
        if isinstance(arg, str):
            arg = arg.encode('utf-8')
        elif not isinstance(arg, (bytes, bytearray)):
            raise TypeError('input must be bytes or string')

        self._unprocessed += arg
        self._message_byte_length += len(arg)

        while len(self._unprocessed) >= 64:
            self._process_chunk(self._unprocessed[:64])
            self._unprocessed = self._unprocessed[64:]

        return self

    def _process_chunk(self, chunk):
        w = list(struct.unpack('>16L', chunk)) + [0]*48

        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ right_shift(w[i - 15], 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ right_shift(w[i - 2], 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

        self._h = [(x + y) & 0xFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e, f, g, h])]

    def digest(self):
        return b''.join(struct.pack('>L', h) for h in self._produce_digest())

    def hexdigest(self):
        return to_hex(self.digest())

    def _produce_digest(self):
        message = self._unprocessed
        message_len = self._message_byte_length

        message += b'\x80'
        message += b'\x00' * ((56 - (message_len + 1) % 64) % 64)
        message_bit_length = message_len * 8
        message += struct.pack('>Q', message_bit_length)

        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

        return self._h

    def copy(self):
        clone = SHA256()
        clone._h = self._h[:]
        clone._unprocessed = self._unprocessed
        clone._message_byte_length = self._message_byte_length
        return clone

class HMAC_SHA256:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        elif not isinstance(key, (bytes, bytearray)):
            raise TypeError('key must be bytes or string')

        if len(key) > 64:
            key = SHA256().update(key).digest()
        if len(key) < 64:
            key += b'\x00' * (64 - len(key))

        self.o_key_pad = bytes((b ^ 0x5C) for b in key)
        self.i_key_pad = bytes((b ^ 0x36) for b in key)

        self.inner = SHA256()
        self.inner.update(self.i_key_pad)

    def update(self, msg):
        self.inner.update(msg)
        return self

    def digest(self):
        inner_digest = self.inner.copy().digest()
        outer = SHA256()
        outer.update(self.o_key_pad)
        outer.update(inner_digest)
        return outer.digest()

    def hexdigest(self):
        return to_hex(self.digest())

def sha256(data):
    return SHA256().update(data).digest()

def sha256_hex(data):
    return SHA256().update(data).hexdigest()

def hmac_sha256(key, data):
    return HMAC_SHA256(key).update(data).digest()

def hmac_sha256_hex(key, data):
    return HMAC_SHA256(key).update(data).hexdigest()

def run_tests():
    print("=== SHA256 Test ===")
    message = "hello world"
    hash_obj = SHA256()
    hash_obj.update(message)
    print("SHA256(hex):", hash_obj.hexdigest())

    print("\n=== HMAC-SHA256 Test ===")
    key = "secret"
    hmac_obj = HMAC_SHA256(key)
    hmac_obj.update(message)
    print("HMAC-SHA256(hex):", hmac_obj.hexdigest())

    # Karşılaştırma: hashlib ile
    import hashlib, hmac as py_hmac
    py_hash = hashlib.sha256(message.encode()).hexdigest()
    py_hmac_val = py_hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

    print("\nReference SHA256 (hashlib):", py_hash)
    print("Reference HMAC-SHA256 (hmac):", py_hmac_val)

if __name__ == "__main__":
    run_tests()
