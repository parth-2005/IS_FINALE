# infoSec/simpleCrypto.py
import random
from Crypto.Cipher import AES
import os

# --- START: FAST PRIMALITY TEST (MILLER-RABIN) ---
def is_prime(n, k=128):
    """
    Test if a number is prime using the Miller-Rabin primality test.
    k is the number of rounds of testing to perform.
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find s and r such that n - 1 = 2^s * r
    s = 0
    r = n - 1
    while r & 1 == 0: # while r is even
        s += 1
        r //= 2
    # perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True
# --- END: FAST PRIMALITY TEST ---

def generate_prime(bits):
    """Generate a prime number of a given bit size."""
    while True:
        # Generate a random number of the correct bit size
        n = random.getrandbits(bits)
        # Ensure it's odd and has the top bit set to guarantee its size
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

def generate_keypair(key_size=256):
    """Generate an RSA keypair."""
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Standard public exponent
    e = 65537
    
    # Ensure e and phi are coprime.
    while extended_gcd(e, phi)[0] != 1:
        p = generate_prime(key_size // 2)
        q = generate_prime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def generate_aes_key(key_size=16):
    """Generates a secure random AES key."""
    return os.urandom(key_size)

def simple_pad(data: bytes, block_size: int) -> bytes:
    """Pads data to a multiple of block_size."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def simple_unpad(data: bytes) -> bytes:
    """Removes padding from data."""
    padding_length = data[-1]
    if padding_length > len(data) or padding_length == 0:
         raise ValueError("Invalid padding length.")
    
    # Check if all padding bytes are correct
    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            raise ValueError("Invalid padding bytes.")
            
    return data[:-padding_length]

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypts a string with AES-CBC and returns iv + ciphertext."""
    try:
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = plaintext.encode('utf-8')
        padded_data = simple_pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypts iv + ciphertext and returns a string."""
    try:
        if len(ciphertext) < AES.block_size:
            raise ValueError("Invalid ciphertext length (too short).")
        
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        
        if len(ct) % AES.block_size != 0:
             raise ValueError("Ciphertext length is not a multiple of block size.")

        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ct)
        
        # Remove padding and convert to string
        plaintext = simple_unpad(padded_plaintext)
        return plaintext.decode('utf-8')
    except Exception as e:
        # Re-raise as a ValueError for clarity
        raise ValueError(f"Decryption failed: {str(e)}")
