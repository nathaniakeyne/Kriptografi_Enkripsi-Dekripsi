import random
import math

# --- 1. CAESAR CIPHER ---
def caesar_encrypt(text, shift):
    result = ""
    steps = []
    for i, char in enumerate(text):
        if char.isascii() and char.isalpha():
            base = 65 if char.isupper() else 97
            p_num = ord(char) - base
            c_num = (p_num + shift) % 26
            res_char = chr(c_num + base)
            steps.append(f"Karakter {i+1} ('{char}'): ({p_num} + {shift}) mod 26 = {c_num} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('{char}'): Bukan huruf -> '{char}'")
            result += char
    return result, steps

def caesar_decrypt(text, shift):
    result = ""
    steps = []
    for i, char in enumerate(text):
        if char.isascii() and char.isalpha():
            base = 65 if char.isupper() else 97
            c_num = ord(char) - base
            p_num = (c_num - shift) % 26
            res_char = chr(p_num + base)
            steps.append(f"Karakter {i+1} ('{char}'): ({c_num} - {shift}) mod 26 = {p_num} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('{char}'): Bukan huruf -> '{char}'")
            result += char
    return result, steps


# --- 2. VIGENERE CIPHER ---
def extend_key(text, key):
    if not key:
        raise ValueError("Kunci Vigenere tidak boleh kosong.")
    return (key * (len(text) // len(key) + 1))[:len(text)]

def vigenere_encrypt(text, key):
    key = extend_key(text, key)
    result = ""
    steps = []
    for i, char in enumerate(text):
        if char.isascii() and char.isalpha():
            base = 65 if char.isupper() else 97
            k_base = 65 if key[i].isupper() else 97
            p_num = ord(char) - base
            shift = ord(key[i]) - k_base
            c_num = (p_num + shift) % 26
            res_char = chr(c_num + base)
            steps.append(f"Karakter {i+1} ('{char}' + Kunci '{key[i]}'): ({p_num} + {shift}) mod 26 = {c_num} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('{char}'): Bukan huruf -> '{char}'")
            result += char
    return result, steps

def vigenere_decrypt(text, key):
    key = extend_key(text, key)
    result = ""
    steps = []
    for i, char in enumerate(text):
        if char.isascii() and char.isalpha():
            base = 65 if char.isupper() else 97
            k_base = 65 if key[i].isupper() else 97
            c_num = ord(char) - base
            shift = ord(key[i]) - k_base
            p_num = (c_num - shift) % 26
            res_char = chr(p_num + base)
            steps.append(f"Karakter {i+1} ('{char}' - Kunci '{key[i]}'): ({c_num} - {shift}) mod 26 = {p_num} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('{char}'): Bukan huruf -> '{char}'")
            result += char
    return result, steps


# --- 3. AES SEDERHANA ---
def aes_encrypt(text, key=1):
    result = ""
    steps = []
    for i, c in enumerate(text):
        if c != " ":
            res_char = chr((ord(c) + key) % 256)
            steps.append(f"Karakter {i+1} ('{c}'): ASCII ({ord(c)}) + Offset ({key}) mod 256 = {ord(res_char)} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('Spasi'): Tetap Spasi")
            result += c
    return result, steps

def aes_decrypt(text, key=1):
    result = ""
    steps = []
    for i, c in enumerate(text):
        if c != " ":
            res_char = chr((ord(c) - key) % 256)
            steps.append(f"Karakter {i+1} ('{c}'): ASCII ({ord(c)}) - Offset ({key}) mod 256 = {ord(res_char)} -> '{res_char}'")
            result += res_char
        else:
            steps.append(f"Karakter {i+1} ('Spasi'): Tetap Spasi")
            result += c
    return result, steps


# --- 4. RC4 ---
class RC4:
    def __init__(self, key):
        if not key:
            raise ValueError("Kunci RC4 tidak boleh kosong.")
        self.S = list(range(256))
        self.i = self.j = 0
        key_bytes = key.encode("latin-1")
        
        j = 0
        for k in range(256):
            j = (j + self.S[k] + key_bytes[k % len(key_bytes)]) % 256
            self.S[k], self.S[j] = self.S[j], self.S[k]

    def get_next_keystream_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    def process(self, data):
        res_bytes = []
        steps = []
        for idx, b in enumerate(data):
            ks = self.get_next_keystream_byte()
            out_b = b ^ ks
            res_bytes.append(out_b)
            p_bin = format(b, '08b')
            k_bin = format(ks, '08b')
            res_bin = format(out_b, '08b')
            steps.append(
                f"Byte {idx+1}:\n"
                f"  Input    : {p_bin} ({b})\n"
                f"  Keystream: {k_bin} ({ks})\n"
                f"  XOR Hasil: {res_bin} ({out_b})"
            )
        return bytes(res_bytes), steps


def rc4_encrypt(text, key):
    raw_bytes, steps = RC4(key).process(text.encode("latin-1"))
    hex_result = raw_bytes.hex(" ").upper()
    return hex_result, steps

def rc4_decrypt(ciphertext_hex, key):
    try:
        data = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError("Ciphertext RC4 harus berupa HEX yang valid.")
    raw_bytes, steps = RC4(key).process(data)
    text_result = raw_bytes.decode("latin-1")
    return text_result, steps

# --- 4. RSA (MODERN - ASIMETRIS) ---

def rsa_is_prime(n, k=20):
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
    """Return (res_string, steps) - format sama kayak caesar_encrypt dkk."""
    block_size = rsa_get_block_size(n)
    data = text.encode("utf-8")
    pad_len = (-len(data)) % block_size
    data += b"\x00" * pad_len

    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    int_blocks = [int.from_bytes(b, "big") for b in blocks]

    cipher_blocks = []
    steps = []
    for idx, m in enumerate(int_blocks):
        c = pow(m, e, n)
        cipher_blocks.append(c)
        steps.append(f"Blok {idx+1}: M={m} -> C = {m}^{e} mod {n} = {c}")

    res = ",".join(str(c) for c in cipher_blocks)
    return res, steps


def rsa_decrypt(ciphertext_str, d, n):
    """Input: string angka dipisah koma. Return (plaintext, steps)."""
    block_size = rsa_get_block_size(n)
    try:
        cipher_blocks = [int(x) for x in ciphertext_str.strip().split(",")]
    except ValueError:
        raise ValueError("Ciphertext RSA harus berupa angka dipisah koma (misal: 123,456,789)")

    int_blocks = []
    steps = []
    for idx, c in enumerate(cipher_blocks):
        m = pow(c, d, n)
        int_blocks.append(m)
        steps.append(f"Blok {idx+1}: C={c} -> M = {c}^{d} mod {n} = {m}")

    data = b"".join(i.to_bytes(block_size, "big") for i in int_blocks)
    text_result = data.rstrip(b"\x00").decode("utf-8", errors="ignore")
    return text_result, steps

# --- 5. SUPER ENKRIPSI ---

def super_encrypt(text, c_shift, v_key, a_key, e, n):
    summary = {}
    details = {}

    res1, steps1 = caesar_encrypt(text, c_shift)
    summary["1. Caesar"] = res1
    details["1. Caesar"] = steps1

    res2, steps2 = vigenere_encrypt(res1, v_key)
    summary["2. Vigenere"] = res2
    details["2. Vigenere"] = steps2

    res3, steps3 = aes_encrypt(res2, a_key)
    summary["3. AES"] = res3
    details["3. AES"] = steps3

    res4, steps4 = rsa_encrypt(res3, e, n)
    summary["4. RSA"] = res4
    details["4. RSA"] = steps4

    return res4, summary, details


def super_decrypt(ciphertext, c_shift, v_key, a_key, d, n):
    summary = {}
    details = {}

    res1, steps1 = rsa_decrypt(ciphertext, d, n)
    summary["4. RSA"] = res1
    details["4. RSA"] = steps1

    res2, steps2 = aes_decrypt(res1, a_key)
    summary["3. AES"] = res2
    details["3. AES"] = steps2

    res3, steps3 = vigenere_decrypt(res2, v_key)
    summary["2. Vigenere"] = res3
    details["2. Vigenere"] = steps3

    res4, steps4 = caesar_decrypt(res3, c_shift)
    summary["1. Caesar"] = res4
    details["1. Caesar"] = steps4

    return res4, summary, details