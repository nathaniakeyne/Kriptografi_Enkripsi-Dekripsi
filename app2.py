import streamlit as st
import kripto2

st.set_page_config(page_title="Aplikasi Kriptografi", layout="wide")

st.title("Aplikasi Enkripsi & Dekripsi Kriptografi")
st.caption("Implementasi Algoritma Klasik, Modern, dan Super Enkripsi")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Caesar Cipher", 
    "2. Vigenere Cipher", 
    "3. AES", 
    "4. RC4", 
    "5. Super Enkripsi"
])

# ------------------- TAB 1: CAESAR CIPHER -------------------
with tab1:
    st.header("1. Caesar Cipher")
    text_input = st.text_area("Masukkan teks:", value="", key="c_text")
    shift_val = st.number_input("Jumlah pergeseran:", value=4, step=1, key="c_shift")
    
    col1, col2 = st.columns(2)
    
    if col1.button("Enkripsi", key="c_enc_btn"):
        if text_input:
            res, steps = kripto2.caesar_encrypt(text_input, shift_val)
            st.success("Hasil Enkripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Enkripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Masukkan teks terlebih dahulu!")

    if col2.button("Dekripsi", key="c_dec_btn"):
        if text_input:
            res, steps = kripto2.caesar_decrypt(text_input, shift_val)
            st.success("Hasil Dekripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Dekripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Masukkan teks terlebih dahulu!")

# ------------------- TAB 2: VIGENERE CIPHER -------------------
with tab2:
    st.header("2. Vigenere Cipher")
    text_input = st.text_area("Masukkan teks:", value="", key="v_text")
    key_input = st.text_input("Masukkan Kunci:", value="KEY", key="v_key")
    
    col1, col2 = st.columns(2)
    if col1.button("Enkripsi", key="v_enc_btn"):
        if text_input and key_input:
            res, steps = kripto2.vigenere_encrypt(text_input, key_input)
            st.success("Hasil Enkripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Enkripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Teks dan Kunci harus diisi!")

    if col2.button("Dekripsi", key="v_dec_btn"):
        if text_input and key_input:
            res, steps = kripto2.vigenere_decrypt(text_input, key_input)
            st.success("Hasil Dekripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Dekripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Teks dan Kunci harus diisi!")

# ------------------- TAB 3: AES SEDERHANA -------------------
with tab3:
    st.header("3. AES")
    text_input = st.text_area("Masukkan teks:", value="", key="a_text")
    key_input = st.number_input("Masukkan Kunci (Sederhana/Offset):", value=1, step=1, key="a_key")
    
    col1, col2 = st.columns(2)
    if col1.button("Enkripsi", key="a_enc_btn"):
        if text_input:
            res, steps = kripto2.aes_encrypt(text_input, key_input)
            st.success("Hasil Enkripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Enkripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Masukkan teks terlebih dahulu!")

    if col2.button("Dekripsi", key="a_dec_btn"):
        if text_input:
            res, steps = kripto2.aes_decrypt(text_input, key_input)
            st.success("Hasil Dekripsi:")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Dekripsi"):
                for step in steps:
                    st.write(f"- {step}")
        else:
            st.warning("Masukkan teks terlebih dahulu!")

# ------------------- TAB 4: RC4 -------------------
with tab4:
    st.header("4. RC4")
    text_input = st.text_area("Masukkan teks / Hex (untuk Dekripsi):", value="", key="r_text")
    key_input = st.text_input("Masukkan Kunci RC4:", value="KEY", key="r_key")
    
    col1, col2 = st.columns(2)
    if col1.button("Enkripsi", key="r_enc_btn"):
        if text_input and key_input:
            res, steps = kripto2.rc4_encrypt(text_input, key_input)
            st.success("Hasil Enkripsi (HEX):")
            st.code(res)
            
            with st.expander("Lihat Langkah-Langkah Bitwise XOR"):
                for step in steps:
                    st.code(step)
        else:
            st.warning("Teks dan Kunci harus diisi!")

    if col2.button("Dekripsi", key="r_dec_btn"):
        if text_input and key_input:
            try:
                res, steps = kripto2.rc4_decrypt(text_input, key_input)
                st.success("Hasil Dekripsi:")
                st.code(res)
                
                with st.expander("Lihat Langkah-Langkah Bitwise XOR"):
                    for step in steps:
                        st.code(step)
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Ciphertext Hex dan Kunci harus diisi!")

# ------------------- TAB 5: SUPER ENKRIPSI -------------------
with tab5:
    st.header("5. Super Enkripsi")
    st.caption("Urutan Enkripsi: 1. Caesar -> 2. Vigenere -> 3. AES Sederhana -> 4. RC4")
    
    text_input = st.text_area("Masukkan teks:", value="", key="s_text")
    
    st.subheader("Parameter Kunci Ke-4 Algoritma")
    
    k_col1, k_col2, k_col3, k_col4 = st.columns(4)
    with k_col1:
        c_shift = st.number_input("1. Caesar Shift:", value=3, step=1, key="s_cshift")
    with k_col2:
        v_key = st.text_input("2. Vigenere Key:", value="KEY", key="s_vkey")
    with k_col3:
        a_key = st.number_input("3. AES Offset:", value=1, step=1, key="s_akey")
    with k_col4:
        r_key = st.text_input("4. RC4 Key:", value="STREAM", key="s_rkey")
    
    btn_col1, btn_col2 = st.columns(2)
    
    if btn_col1.button("Enkripsi Super", key="s_enc_btn"):
        if text_input and v_key and r_key:
            res, summary, details = kripto2.super_encrypt(text_input, c_shift, v_key, a_key, r_key)
            st.success("Hasil Akhir Super Enkripsi (HEX):")
            st.code(res)
            
            st.subheader("Ringkasan Output Per Tahap")
            for stage, output in summary.items():
                st.write(f"**{stage}:** `{output}`")
                
            st.subheader("Rincian Perhitungan Per Tahap")
            for stage_name, steps in details.items():
                with st.expander(f"Detail {stage_name}"):
                    for step in steps:
                        st.write(step)
        else:
            st.warning("Pastikan semua masukan dan kunci diisi!")

    if btn_col2.button("Dekripsi Super", key="s_dec_btn"):
        if text_input and v_key and r_key:
            try:
                res, summary, details = kripto2.super_decrypt(text_input, c_shift, v_key, a_key, r_key)
                st.success("Hasil Akhir Super Dekripsi (Plaintext):")
                st.code(res)
                
                st.subheader("Ringkasan Output Per Tahap")
                for stage, output in summary.items():
                    st.write(f"**{stage}:** `{output}`")
                    
                st.subheader("Rincian Perhitungan Per Tahap")
                for stage_name, steps in details.items():
                    with st.expander(f"Detail {stage_name}"):
                        for step in steps:
                            st.write(step)
            except Exception as e:
                st.error(f"Error saat dekripsi: {e}")
        else:
            st.warning("Pastikan Ciphertext HEX dan semua kunci diisi!")