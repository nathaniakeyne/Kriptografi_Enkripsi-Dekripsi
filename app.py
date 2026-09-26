import streamlit as st
import kripto

st.set_page_config(
    page_title="Aplikasi Kriptografi",
    layout="wide"
)

st.title("Aplikasi Enkripsi & Dekripsi Kriptografi")
st.caption("Implementasi Algoritma Klasik, Stream Cipher, Asimetris, dan Super Enkripsi")

# Simpan keypair RSA di session_state supaya konsisten dipakai
# antara Enkripsi & Dekripsi (dan antar Tab 4 & Tab 5)
if "rsa_bits" not in st.session_state:
    st.session_state.rsa_bits = 16

if "rsa_keypair" not in st.session_state:
    st.session_state.rsa_keypair = kripto.rsa_generate_keypair(
        bits=st.session_state.rsa_bits
    )

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Rail Fence",
    "2. Vigenere",
    "3. RC4",
    "4. RSA",
    "5. Super Enkripsi"
])

# TAB 1 - RAIL FENCE
with tab1:
    st.header("1. Rail Fence Cipher")

    text_input = st.text_area(
        "Masukkan teks:",
        key="rail_text"
    )

    rail = st.number_input(
        "Jumlah Rail:",
        min_value=2,
        value=3,
        step=1,
        key="rail_number"
    )

    col1, col2 = st.columns(2)

    if col1.button("Enkripsi", key="rail_enc"):
        if text_input:
            hasil, steps = kripto.rail_fence_encrypt(
                text_input, rail
            )

            st.success("Hasil Enkripsi:")
            st.code(hasil)

            with st.expander("Lihat Langkah-Langkah Enkripsi"):
                for step in steps:
                    st.write(step)
        else:
            st.warning("Masukkan teks terlebih dahulu!")

    if col2.button("Dekripsi", key="rail_dec"):
        if text_input:
            hasil, steps = kripto.rail_fence_decrypt(
                text_input, rail
            )

            st.success("Hasil Dekripsi:")
            st.code(hasil)

            with st.expander("Lihat Langkah-Langkah Dekripsi"):
                for step in steps:
                    st.write(step)
        else:
            st.warning("Masukkan teks terlebih dahulu!")

# TAB 2 - VIGENERE
with tab2:
    st.header("2. Vigenere Cipher")

    text_input = st.text_area(
        "Masukkan teks:",
        key="vig_text"
    )

    key_input = st.text_input(
        "Masukkan Kunci:",
        value="KEY",
        key="vig_key"
    )

    col1, col2 = st.columns(2)

    if col1.button("Enkripsi", key="vig_enc"):
        if text_input and key_input:
            hasil, steps = kripto.vigenere_encrypt(
                text_input, key_input
            )

            st.success("Hasil Enkripsi:")
            st.code(hasil)

            with st.expander("Lihat Langkah-Langkah Enkripsi"):
                for step in steps:
                    st.write(step)
        else:
            st.warning("Teks dan kunci harus diisi!")

    if col2.button("Dekripsi", key="vig_dec"):
        if text_input and key_input:
            hasil, steps = kripto.vigenere_decrypt(
                text_input, key_input
            )

            st.success("Hasil Dekripsi:")
            st.code(hasil)

            with st.expander("Lihat Langkah-Langkah Dekripsi"):
                for step in steps:
                    st.write(step)
        else:
            st.warning("Teks dan kunci harus diisi!")

# TAB 3 - RC4
with tab3:
    st.header("3. RC4")

    text_input = st.text_area(
        "Masukkan teks / HEX untuk dekripsi:",
        key="rc4_text"
    )

    key_input = st.text_input(
        "Masukkan Kunci RC4:",
        value="KEY",
        key="rc4_key"
    )

    col1, col2 = st.columns(2)

    if col1.button("Enkripsi", key="rc4_enc"):
        if text_input and key_input:
            try:
                hasil, steps = kripto.rc4_encrypt(
                    text_input, key_input
                )

                st.success("Hasil Enkripsi (HEX):")
                st.code(hasil)

                with st.expander("Lihat Langkah-Langkah RC4"):
                    for step in steps:
                        st.code(step)
            except Exception as e:
                st.error("Error: " + str(e))
        else:
            st.warning("Teks dan kunci harus diisi!")

    if col2.button("Dekripsi", key="rc4_dec"):
        if text_input and key_input:
            try:
                hasil, steps = kripto.rc4_decrypt(
                    text_input, key_input
                )

                st.success("Hasil Dekripsi:")
                st.code(hasil)

                with st.expander("Lihat Langkah-Langkah RC4"):
                    for step in steps:
                        st.code(step)
            except Exception as e:
                st.error("Error: " + str(e))
        else:
            st.warning("Ciphertext HEX dan kunci harus diisi!")

# TAB 4 - RSA
with tab4:
    st.header("4. RSA")

    BIT_OPTIONS = [8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512]

    if st.session_state.rsa_bits not in BIT_OPTIONS:
        # jaga-jaga kalau ada nilai lama yang sudah tidak ada di daftar
        st.session_state.rsa_bits = 16

    col_bits, col_btn, col_status = st.columns([2, 1, 2])

    with col_bits:
        bits_choice = st.selectbox(
            "Ukuran bit tiap prima (p, q):",
            options=BIT_OPTIONS,
            index=BIT_OPTIONS.index(st.session_state.rsa_bits),
            key="rsa_bits_select",
            help=(
                "Semakin besar bit, semakin lama proses generate prime "
                "dan semakin besar angka hasil enkripsi. n = p * q, jadi "
                "n akan berukuran kurang lebih 2x bit yang dipilih. "
                "Untuk 256-bit ke atas, proses generate bisa memakan "
                "waktu beberapa detik karena pencarian prima dilakukan "
                "murni di Python."
            )
        )

    with col_btn:
        st.write("")
        st.write("")
        generate_clicked = st.button("Generate Key RSA", key="rsa_regen")

    if generate_clicked:
        st.session_state.rsa_bits = bits_choice
        with st.spinner(f"Membuat prime {bits_choice}-bit..."):
            st.session_state.rsa_keypair = kripto.rsa_generate_keypair(
                bits=bits_choice
            )

    with col_status:
        st.write("")
        st.write("")
        aktif_bits = st.session_state.rsa_bits
        aktif_n_bits = st.session_state.rsa_keypair["n"].bit_length()
        st.success(f"Key aktif: {aktif_bits}-bit (n = {aktif_n_bits}-bit)")

    block_size_info = kripto.rsa_get_block_size(
        st.session_state.rsa_keypair["n"]
    )
    st.caption(
        f"n saat ini berukuran {st.session_state.rsa_keypair['n'].bit_length()} bit "
        f"-> ukuran blok teks per enkripsi = {block_size_info} byte. "
        "Semakin kecil bit, semakin kecil pula blok teks yang bisa "
        "dienkripsi sekali proses (tapi tetap otomatis dipecah per blok)."
    )

    keypair = st.session_state.rsa_keypair
    e, d, n = keypair["e"], keypair["d"], keypair["n"]

    with st.expander("Lihat Key RSA", expanded=True):
        st.write(f"p = {keypair['p']}")
        st.write(f"q = {keypair['q']}")
        st.write(f"n = {keypair['n']}")
        st.write(f"phi(n) = {keypair['phi']}")

        key_steps = (
            kripto.rsa_key_info(e, n, "Public (e, n)")
            + kripto.rsa_key_info(d, n, "Private (d, n)")
        )

        for step in key_steps:
            st.write(step)

    text_input = st.text_area(
        "Masukkan teks / ciphertext RSA:",
        key="rsa_text"
    )

    col1, col2 = st.columns(2)

    if col1.button("Enkripsi", key="rsa_enc"):
        if text_input:
            try:
                hasil, steps = kripto.rsa_encrypt(
                    text_input, e, n
                )

                st.success("Hasil Enkripsi RSA:")
                st.code(hasil)

                with st.expander("Lihat Langkah-Langkah RSA"):
                    for step in kripto.rsa_key_info(e, n, "Public (e, n)"):
                        st.write(step)

                    for step in steps:
                        st.write(step)
            except Exception as e_err:
                st.error("Error: " + str(e_err))
        else:
            st.warning("Masukkan teks terlebih dahulu!")

    if col2.button("Dekripsi", key="rsa_dec"):
        if text_input:
            try:
                hasil, steps = kripto.rsa_decrypt(
                    text_input, d, n
                )

                st.success("Hasil Dekripsi RSA:")
                st.code(hasil)

                with st.expander("Lihat Langkah-Langkah RSA"):
                    for step in kripto.rsa_key_info(d, n, "Private (d, n)"):
                        st.write(step)

                    for step in steps:
                        st.write(step)
            except Exception as e_err:
                st.error("Ciphertext RSA tidak valid: " + str(e_err))
        else:
            st.warning("Masukkan ciphertext RSA terlebih dahulu!")

# TAB 5 - SUPER ENKRIPSI
with tab5:
    st.header("5. Super Enkripsi")

    st.caption(
        "Urutan: Rail Fence -> Vigenere -> RC4 -> RSA"
    )

    keypair = st.session_state.rsa_keypair
    e, d, n = keypair["e"], keypair["d"], keypair["n"]

    text_input = st.text_area(
        "Masukkan teks:",
        key="super_text"
    )

    st.subheader("Kunci Masing-Masing Algoritma")

    col1, col2, col3 = st.columns(3)

    with col1:
        rail_key = st.number_input(
            "1. Jumlah Rail:",
            min_value=2,
            value=3,
            step=1,
            key="super_rail"
        )

    with col2:
        vig_key = st.text_input(
            "2. Kunci Vigenere:",
            value="KEY",
            key="super_vig"
        )

    with col3:
        rc4_key = st.text_input(
            "3. Kunci RC4:",
            value="STREAM",
            key="super_rc4"
        )

    st.write(f"4. RSA menggunakan:")
    st.write(f"Public Key (e={e}, n={n})")
    st.write(f"Private Key (d={d}, n={n})")
    st.write(
        f"dari menu RSA (prima {st.session_state.rsa_bits}-bit). "
        "Ubah ukuran bit di Tab 4 jika perlu."
    )

    col1, col2 = st.columns(2)

    if col1.button("Enkripsi Super", key="super_enc"):
        if text_input and vig_key and rc4_key:
            try:
                hasil, summary, details = kripto.super_encrypt(
                    text_input,
                    rail_key,
                    vig_key,
                    rc4_key,
                    e,
                    n
                )

                st.success("Hasil Akhir Super Enkripsi:")
                st.code(hasil)

                st.subheader("Ringkasan Output Per Tahap")

                for nama, output in summary.items():
                    st.write("**" + nama + ":**")
                    st.code(output)

                st.subheader("Rincian Perhitungan")

                for nama, steps in details.items():
                    with st.expander("Detail " + nama):
                        for step in steps:
                            st.write(step)

            except Exception as ex:
                st.error("Error: " + str(ex))
        else:
            st.warning(
                "Teks, kunci Vigenere, dan kunci RC4 harus diisi!"
            )

    if col2.button("Dekripsi Super", key="super_dec"):
        if text_input and vig_key and rc4_key:
            try:
                hasil, summary, details = kripto.super_decrypt(
                    text_input,
                    rail_key,
                    vig_key,
                    rc4_key,
                    d,
                    n
                )

                st.success("Hasil Akhir Super Dekripsi:")
                st.code(hasil)

                st.subheader("Ringkasan Output Per Tahap")

                for nama, output in summary.items():
                    st.write("**" + nama + ":**")
                    st.code(output)

                st.subheader("Rincian Perhitungan")

                for nama, steps in details.items():
                    with st.expander("Detail " + nama):
                        for step in steps:
                            st.write(step)

            except Exception as ex:
                st.error("Error saat dekripsi: " + str(ex))
        else:
            st.warning(
                "Ciphertext, kunci Vigenere, dan kunci RC4 harus diisi!"
            )