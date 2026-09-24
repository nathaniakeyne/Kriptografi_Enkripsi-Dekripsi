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


# --- 5. SUPER ENCRYPTION (4 ALGORITMA) ---
def super_encrypt(text, caesar_shift, vigenere_key, aes_key, rc4_key):
    steps_summary = {}
    detailed_steps = {}
    
    # Tahap 1: Caesar Cipher
    res_caesar, s_caesar = caesar_encrypt(text, caesar_shift)
    steps_summary["1. Setelah Caesar Cipher"] = res_caesar
    detailed_steps["1. Caesar Cipher"] = s_caesar
    
    # Tahap 2: Vigenere Cipher
    res_vigenere, s_vigenere = vigenere_encrypt(res_caesar, vigenere_key)
    steps_summary["2. Setelah Vigenere Cipher"] = res_vigenere
    detailed_steps["2. Vigenere Cipher"] = s_vigenere
    
    # Tahap 3: AES Sederhana
    res_aes, s_aes = aes_encrypt(res_vigenere, aes_key)
    steps_summary["3. Setelah AES Sederhana"] = res_aes
    detailed_steps["3. AES Sederhana"] = s_aes
    
    # Tahap 4: RC4
    res_rc4, s_rc4 = rc4_encrypt(res_aes, rc4_key)
    steps_summary["4. Setelah RC4"] = res_rc4
    detailed_steps["4. RC4"] = s_rc4
    
    return res_rc4, steps_summary, detailed_steps

def super_decrypt(ciphertext_hex, caesar_shift, vigenere_key, aes_key, rc4_key):
    steps_summary = {}
    detailed_steps = {}
    
    # Reverse Tahap 1: RC4
    res_rc4, s_rc4 = rc4_decrypt(ciphertext_hex, rc4_key)
    steps_summary["1. Setelah RC4"] = res_rc4
    detailed_steps["1. RC4"] = s_rc4
    
    # Reverse Tahap 2: AES Sederhana
    res_aes, s_aes = aes_decrypt(res_rc4, aes_key)
    steps_summary["2. Setelah AES Sederhana"] = res_aes
    detailed_steps["2. AES Sederhana"] = s_aes
    
    # Reverse Tahap 3: Vigenere Cipher
    res_vigenere, s_vigenere = vigenere_decrypt(res_aes, vigenere_key)
    steps_summary["3. Setelah Vigenere Cipher"] = res_vigenere
    detailed_steps["3. Vigenere Cipher"] = s_vigenere
    
    # Reverse Tahap 4: Caesar Cipher
    res_caesar, s_caesar = caesar_decrypt(res_vigenere, caesar_shift)
    steps_summary["4. Setelah Caesar Cipher"] = res_caesar
    detailed_steps["4. Caesar Cipher"] = s_caesar
    
    return res_caesar, steps_summary, detailed_steps