import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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

print("Hello World!")