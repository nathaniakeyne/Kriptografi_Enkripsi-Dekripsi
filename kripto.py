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
# Nilai ini dipakai supaya contoh RSA mudah dipelajari.
P = 61
Q = 53
N = P * Q
PHI = (P - 1) * (Q - 1)
E = 17
D = 2753


def rsa_key_info():
    steps = [
        "p = " + str(P),
        "q = " + str(Q),
        "n = p x q = " + str(P) + " x " + str(Q) + " = " + str(N),
        "phi(n) = (p - 1) x (q - 1) = " + str(PHI),
        "Public exponent (e) = " + str(E),
        "Private exponent (d) = " + str(D),
        "Public Key = (" + str(E) + ", " + str(N) + ")",
        "Private Key = (" + str(D) + ", " + str(N) + ")"
    ]

    return steps


def rsa_encrypt(text):
    hasil = []
    steps = []

    for i in range(len(text)):
        m = ord(text[i])

        if m >= N:
            raise ValueError("Karakter terlalu besar untuk contoh RSA ini.")

        c = pow(m, E, N)
        hasil.append(str(c))

        steps.append(
            "Karakter ke-" + str(i + 1) +
            " '" + text[i] + "' -> M = " + str(m) +
            " -> C = " + str(m) + "^" + str(E) +
            " mod " + str(N) + " = " + str(c)
        )

    hasil_text = " ".join(hasil)

    return hasil_text, steps


def rsa_decrypt(ciphertext):
    if ciphertext.strip() == "":
        return "", []

    angka = ciphertext.split()
    hasil = ""
    steps = []

    for i in range(len(angka)):
        c = int(angka[i])
        m = pow(c, D, N)

        hasil = hasil + chr(m)

        steps.append(
            "Cipher ke-" + str(i + 1) +
            " C = " + str(c) +
            " -> M = " + str(c) + "^" + str(D) +
            " mod " + str(N) + " = " + str(m) +
            " -> '" + chr(m) + "'"
        )

    return hasil, steps

# 5. SUPER ENKRIPSI
def super_encrypt(text, rail, vigenere_key, rc4_key):
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
    hasil_rsa, step_rsa = rsa_encrypt(hasil_rc4)
    summary["4. Setelah RSA"] = hasil_rsa
    details["4. RSA"] = rsa_key_info() + step_rsa

    return hasil_rsa, summary, details


def super_decrypt(ciphertext, rail, vigenere_key, rc4_key):
    summary = {}
    details = {}

    # Balik dari RSA
    hasil_rsa, step_rsa = rsa_decrypt(ciphertext)
    summary["1. Setelah RSA"] = hasil_rsa
    details["1. RSA"] = rsa_key_info() + step_rsa

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
