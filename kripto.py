import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- 1. CAESAR CIPHER ---
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# --- 2. VIGENERE CIPHER ---
def vigenere_encrypt(text, key):
    result = []
    key = key.lower()
    key_length = len(key)
    key_indices = [ord(k) - ord('a') for k in key if k.isalpha()]
    
    if not key_indices:
        return text

    key_idx = 0
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = key_indices[key_idx % len(key_indices)]
            result.append(chr((ord(char) - start + shift) % 26 + start))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)

def vigenere_decrypt(text, key):
    result = []
    key = key.lower()
    key_indices = [ord(k) - ord('a') for k in key if k.isalpha()]
    
    if not key_indices:
        return text

    key_idx = 0
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = key_indices[key_idx % len(key_indices)]
            result.append(chr((ord(char) - start - shift) % 26 + start))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)

# --- 3. STREAM CIPHER (MODERN - BERBASIS BIT XOR / KEYSTREAM) ---
# Mengimplementasikan prinsip stream cipher bit per bit (p_i XOR k_i) sesuai PDF
def stream_cipher_process(text, key_str):
    if not key_str:
        return text
    
    text_bytes = text.encode('utf-8')
    key_bytes = key_str.encode('utf-8')
    
    # Menghasilkan keystream secara berulang selaras dengan panjang bit/byte data
    processed_bytes = bytearray()
    for i in range(len(text_bytes)):
        k_i = key_bytes[i % len(key_bytes)]
        p_i = text_bytes[i]
        processed_bytes.append(p_i ^ k_i)  # Operasi Bitwise XOR
        
    return processed_bytes

def stream_cipher_encrypt(text, key_str):
    encrypted_bytes = stream_cipher_process(text, key_str)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def stream_cipher_decrypt(cipher_text_b64, key_str):
    try:
        decoded_bytes = base64.b64decode(cipher_text_b64.encode('utf-8'))
        # Operasi XOR bersifat bolak-balik: (c_i XOR k_i) = p_i
        decrypted_bytes = bytearray()
        key_bytes = key_str.encode('utf-8')
        for i in range(len(decoded_bytes)):
            k_i = key_bytes[i % len(key_bytes)]
            c_i = decoded_bytes[i]
            decrypted_bytes.append(c_i ^ k_i)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"Error Dekripsi Stream Cipher: {str(e)}"

# 4. Kriptografi Modern Asimetris RSA (Rivest–Shamir–Adleman)

import random
import math

def rsa_is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if rsa_is_prime(candidate):
            return candidate


def rsa_extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = rsa_extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def rsa_mod_inverse(e, phi):
    g, d, _ = rsa_extended_gcd(e, phi)
    if g != 1:
        raise ValueError(f"e={e} tidak coprime dengan phi={phi}")
    return d % phi


def rsa_generate_keypair(bits=16):
    """Return dict berisi p, q, n, phi, e, d."""
    p = rsa_generate_prime(bits)
    q = rsa_generate_prime(bits)
    while q == p:
        q = rsa_generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = rsa_mod_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def rsa_get_block_size(n):
    return max((n.bit_length() - 1) // 8, 1)


def rsa_encrypt(text, e, n):
    """Return (cipher_blocks: list[int], block_size: int)."""
    block_size = rsa_get_block_size(n)
    data = text.encode("utf-8")

    pad_len = (-len(data)) % block_size
    data += b"\x00" * pad_len

    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    int_blocks = [int.from_bytes(b, "big") for b in blocks]

    return [pow(m, e, n) for m in int_blocks], block_size


def rsa_decrypt(cipher_blocks, d, n, block_size):
    """cipher_blocks: list[int] -> return teks hasil dekripsi."""
    int_blocks = [pow(c, d, n) for c in cipher_blocks]
    data = b"".join(i.to_bytes(block_size, "big") for i in int_blocks)
    return data.rstrip(b"\x00").decode("utf-8", errors="ignore")