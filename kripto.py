import random
import math
# 1. RAIL FENCE CIPHER
def rail_fence_encrypt(text, rails):
    if rails < 2:
        return text, ["Jumlah rail kurang dari 2, jadi teks tidak berubah."]

    fence = []
    for i in range(rails):
        fence.append([])

    rail = 0
    arah = 1
    steps = []

    for i in range(len(text)):
        char = text[i]
        fence[rail].append(char)

        steps.append(
            "Karakter ke-" + str(i + 1) +
            " ('" + char + "') dimasukkan ke Rail " + str(rail + 1)
        )

        if rail == 0:
            arah = 1
        elif rail == rails - 1:
            arah = -1

        rail = rail + arah

    hasil = ""

    for i in range(rails):
        hasil = hasil + "".join(fence[i])

    steps.append("Hasil setiap rail:")
    for i in range(rails):
        steps.append("Rail " + str(i + 1) + ": " + "".join(fence[i]))

    steps.append("Ciphertext: " + hasil)

    return hasil, steps


def rail_fence_decrypt(text, rails):
    if rails < 2:
        return text, ["Jumlah rail kurang dari 2, jadi teks tidak berubah."]

    panjang = len(text)
    pola = []

    rail = 0
    arah = 1

    for i in range(panjang):
        pola.append(rail)

        if rail == 0:
            arah = 1
        elif rail == rails - 1:
            arah = -1

        rail = rail + arah

    jumlah = []
    for i in range(rails):
        jumlah.append(0)

    for nomor in pola:
        jumlah[nomor] = jumlah[nomor] + 1

    fence = []
    posisi = 0

    for i in range(rails):
        bagian = []
        for j in range(jumlah[i]):
            bagian.append(text[posisi])
            posisi = posisi + 1
        fence.append(bagian)

    indeks = []
    for i in range(rails):
        indeks.append(0)

    hasil = ""
    steps = []

    for i in range(panjang):
        nomor_rail = pola[i]
        hasil = hasil + fence[nomor_rail][indeks[nomor_rail]]

        steps.append(
            "Karakter ke-" + str(i + 1) +
            " diambil dari Rail " + str(nomor_rail + 1) +
            " -> '" + fence[nomor_rail][indeks[nomor_rail]] + "'"
        )

        indeks[nomor_rail] = indeks[nomor_rail] + 1

    steps.append("Plaintext: " + hasil)

    return hasil, steps

# 2. VIGENERE CIPHER
def vigenere_encrypt(text, key):
    if key == "":
        raise ValueError("Kunci Vigenere tidak boleh kosong.")

    hasil = ""
    steps = []
    nomor_kunci = 0

    for i in range(len(text)):
        char = text[i]

        if char.isascii() and char.isalpha():
            if key[nomor_kunci % len(key)].isalpha():
                k = key[nomor_kunci % len(key)]
            else:
                k = "A"

            base = 65 if char.isupper() else 97
            p = ord(char) - base

            k_base = 65 if k.isupper() else 97
            nilai_kunci = ord(k.upper()) - 65

            c = (p + nilai_kunci) % 26
            karakter_hasil = chr(c + base)

            hasil = hasil + karakter_hasil

            steps.append(
                "Karakter " + str(i + 1) + " ('" + char + "') + Kunci '" +
                k + "': (" + str(p) + " + " + str(nilai_kunci) +
                ") mod 26 = " + str(c) + " -> '" + karakter_hasil + "'"
            )

            nomor_kunci = nomor_kunci + 1
        else:
            hasil = hasil + char
            steps.append(
                "Karakter " + str(i + 1) + " ('" + char +
                "') bukan huruf -> tetap '" + char + "'"
            )

    return hasil, steps


def vigenere_decrypt(text, key):
    if key == "":
        raise ValueError("Kunci Vigenere tidak boleh kosong.")

    hasil = ""
    steps = []
    nomor_kunci = 0

    for i in range(len(text)):
        char = text[i]

        if char.isascii() and char.isalpha():
            if key[nomor_kunci % len(key)].isalpha():
                k = key[nomor_kunci % len(key)]
            else:
                k = "A"

            base = 65 if char.isupper() else 97
            c = ord(char) - base

            nilai_kunci = ord(k.upper()) - 65
            p = (c - nilai_kunci) % 26

            karakter_hasil = chr(p + base)

            hasil = hasil + karakter_hasil

            steps.append(
                "Karakter " + str(i + 1) + " ('" + char + "') - Kunci '" +
                k + "': (" + str(c) + " - " + str(nilai_kunci) +
                ") mod 26 = " + str(p) + " -> '" + karakter_hasil + "'"
            )

            nomor_kunci = nomor_kunci + 1
        else:
            hasil = hasil + char
            steps.append(
                "Karakter " + str(i + 1) + " ('" + char +
                "') bukan huruf -> tetap '" + char + "'"
            )

    return hasil, steps

# 3. RC4
class RC4:
    def __init__(self, key):
        if key == "":
            raise ValueError("Kunci RC4 tidak boleh kosong.")

        self.S = list(range(256))
        self.i = 0
        self.j = 0

        key_bytes = key.encode("latin-1")

        j = 0
        self.ksa_steps = []

        for i in range(256):
            j = (j + self.S[i] + key_bytes[i % len(key_bytes)]) % 256

            temp = self.S[i]
            self.S[i] = self.S[j]
            self.S[j] = temp

            self.ksa_steps.append(
                "KSA i=" + str(i) +
                ", j=" + str(j) +
                ", S[i]=" + str(self.S[i]) +
                ", S[j]=" + str(self.S[j])
            )

    def get_next_keystream_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256

        temp = self.S[self.i]
        self.S[self.i] = self.S[self.j]
        self.S[self.j] = temp

        posisi = (self.S[self.i] + self.S[self.j]) % 256

        return self.S[posisi]

    def process(self, data):
        hasil = []
        steps = []

        for i in range(len(data)):
            byte_input = data[i]
            keystream = self.get_next_keystream_byte()
            byte_hasil = byte_input ^ keystream

            hasil.append(byte_hasil)

            input_bin = format(byte_input, "08b")
            key_bin = format(keystream, "08b")
            hasil_bin = format(byte_hasil, "08b")

            steps.append(
                "Byte " + str(i + 1) + ":\n" +
                "Input     : " + input_bin + " (" + str(byte_input) + ")\n" +
                "Keystream : " + key_bin + " (" + str(keystream) + ")\n" +
                "XOR Hasil : " + hasil_bin + " (" + str(byte_hasil) + ")"
            )

        return bytes(hasil), steps


def rc4_encrypt(text, key):
    rc4 = RC4(key)
    data = text.encode("latin-1")
    hasil, steps = rc4.process(data)

    semua_steps = []
    semua_steps.append("=== KSA / Key Scheduling Algorithm ===")
    semua_steps.extend(rc4.ksa_steps)
    semua_steps.append("=== PRGA dan XOR ===")
    semua_steps.extend(steps)

    return hasil.hex(" ").upper(), semua_steps


def rc4_decrypt(ciphertext_hex, key):
    try:
        data = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError("Ciphertext RC4 harus berupa HEX yang valid.")

    rc4 = RC4(key)
    hasil, steps = rc4.process(data)

    semua_steps = []
    semua_steps.append("=== KSA / Key Scheduling Algorithm ===")
    semua_steps.extend(rc4.ksa_steps)
    semua_steps.append("=== PRGA dan XOR ===")
    semua_steps.extend(steps)

    return hasil.decode("latin-1"), semua_steps

# 4. RSA
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

def rsa_key_info(key_value, n, label="Key"):
    """
    Bikin 1 baris info kunci yang dipakai, buat ditampilin di 'details'
    Super Enkripsi (sebelumnya dipanggil rsa_key_info() tanpa argumen -
    ini yang bikin error karena fungsinya belum pernah didefinisikan).
    """
    return [f"{label} = ({key_value}, {n})"]

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

# 5. SUPER ENKRIPSI
def super_encrypt(text, rail, vigenere_key, rc4_key, e, n):
    summary = {}
    details = {}
 
    # Tahap 1: Rail Fence
    hasil_rail, step_rail = rail_fence_encrypt(text, rail)
    summary["1. Setelah Rail Fence"] = hasil_rail
    details["1. Rail Fence"] = step_rail
 
    # Tahap 2: Vigenere
    hasil_vigenere, step_vigenere = vigenere_encrypt(
        hasil_rail, vigenere_key
    )
    summary["2. Setelah Vigenere"] = hasil_vigenere
    details["2. Vigenere"] = step_vigenere
 
    # Tahap 3: RC4
    hasil_rc4, step_rc4 = rc4_encrypt(
        hasil_vigenere, rc4_key
    )
    summary["3. Setelah RC4"] = hasil_rc4
    details["3. RC4"] = step_rc4
 
    # Tahap 4: RSA
    hasil_rsa, step_rsa = rsa_encrypt(hasil_rc4, e, n)
    summary["4. Setelah RSA"] = hasil_rsa
    details["4. RSA"] = rsa_key_info(e, n, "Public (e, n)") + step_rsa
 
    return hasil_rsa, summary, details
 
 
def super_decrypt(ciphertext, rail, vigenere_key, rc4_key, d, n):
    summary = {}
    details = {}
 
    # Balik dari RSA
    hasil_rsa, step_rsa = rsa_decrypt(ciphertext, d, n)
    summary["1. Setelah RSA"] = hasil_rsa
    details["1. RSA"] = rsa_key_info(d, n, "Private (d, n)") + step_rsa
 
    # Balik dari RC4
    hasil_rc4, step_rc4 = rc4_decrypt(
        hasil_rsa, rc4_key
    )
    summary["2. Setelah RC4"] = hasil_rc4
    details["2. RC4"] = step_rc4
 
    # Balik dari Vigenere
    hasil_vigenere, step_vigenere = vigenere_decrypt(
        hasil_rc4, vigenere_key
    )
    summary["3. Setelah Vigenere"] = hasil_vigenere
    details["3. Vigenere"] = step_vigenere
 
    # Balik dari Rail Fence
    hasil_rail, step_rail = rail_fence_decrypt(
        hasil_vigenere, rail
    )
    summary["4. Setelah Rail Fence"] = hasil_rail
    details["4. Rail Fence"] = step_rail
 
    return hasil_rail, summary, details
