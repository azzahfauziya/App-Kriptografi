import streamlit as st
import base64

# =========================================================
# CAESAR CIPHER
def caesar_enkripsi(text, shift):
    result = ""
    log = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            new_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            log.append(f"'{char}'  →  geser maju {shift}  →  '{new_char}'")
            result += new_char
        else:
            log.append(f"'{char}'  →  bukan huruf, tetap  →  '{char}'")
            result += char
    return result, log

def caesar_dekripsi(text, shift):
    result = ""
    log = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            new_char = chr((ord(char) - shift_base - shift) % 26 + shift_base)
            log.append(f"'{char}'  →  geser mundur {shift}  →  '{new_char}'")
            result += new_char
        else:
            log.append(f"'{char}'  →  bukan huruf, tetap  →  '{char}'")
            result += char
    return result, log


# =========================================================
# VIGENERE CIPHER
def vigenere_enkripsi(text, key):
    result = ""
    extended_key = ""
    steps = []
    key = "".join(c for c in key if c.isalpha()).lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - 97
            shift_base = 65 if char.isupper() else 97
            new_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)

            extended_key += key_char.upper() if char.isupper() else key_char
            steps.append(f"({char}+{key_char}) mod 26 = {new_char}")

            result += new_char
            key_index += 1
        else:
            extended_key += char
            result += char
    return result, extended_key, steps

def vigenere_dekripsi(text, key):
    result = ""
    extended_key = ""
    steps = []
    key = "".join(c for c in key if c.isalpha()).lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - 97
            shift_base = 65 if char.isupper() else 97
            new_char = chr((ord(char) - shift_base - shift) % 26 + shift_base)

            extended_key += key_char.upper() if char.isupper() else key_char
            steps.append(f"({char}-{key_char}) mod 26 = {new_char}")

            result += new_char
            key_index += 1
        else:
            extended_key += char
            result += char
    return result, extended_key, steps


# =========================================================
# STREAM CIPHER 
def lfsr_keystream(seed, length):
    reg = seed & 0xF or 1
    stream = ""
    for _ in range(length):
        out = reg & 1
        new_bit = ((reg >> 0) ^ (reg >> 3)) & 1
        reg = (reg >> 1) | (new_bit << 3)
        stream += str(out)
    return stream

def stream_cipher_process(text_bits, key_str, mode="enkripsi"):
    seed = ord(key_str[0]) % 16 if key_str else 15
    keystream = lfsr_keystream(seed, len(text_bits))
    result_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(text_bits, keystream))

    label_in = "Plaintext" if mode == "enkripsi" else "Ciphertext"
    label_out = "Ciphertext" if mode == "enkripsi" else "Plaintext"

    log_tahapan = [
        f"[TAHAP 1] Input ({label_in}) dalam bentuk bit:",
        text_bits,
        "",
        f"[TAHAP 2] Keystream dibangkitkan via LFSR (Seed={seed}):",
        keystream,
        "",
        f"[TAHAP 3] Proses XOR (⊕) bit-per-bit:",
        f"  {text_bits}  ({label_in})",
        f"⊕ {keystream}  (Keystream)",
        f"{'-'*len(text_bits)}",
        f"  {result_bits}  ({label_out})"
    ]
    return result_bits, log_tahapan, seed

def stream_chiper_enkripsi(text, key):
    bits = ''.join(format(ord(c), '08b') for c in text)
    cipher_bits, log, seed = stream_cipher_process(bits, key, "enkripsi")

    padding = (8 - len(cipher_bits) % 8) % 8
    padded_bits = cipher_bits + ('0' * padding)

    cipher_bytes = int(padded_bits, 2).to_bytes(len(padded_bits) // 8, byteorder='big')
    cipher_b64 = base64.b64encode(cipher_bytes).decode("utf-8")

    return cipher_b64, log, cipher_bits

def stream_chiper_dekripsi(input_data, key):
    input_data = input_data.strip()
    cipher_bits = ""

    is_binary = all(c in '01' for c in input_data)

    if is_binary and len(input_data) > 0:
        valid_len = (len(input_data) // 8) * 8
        cipher_bits = input_data[:valid_len]
    else:
        try:
            cipher_bytes = base64.b64decode(input_data.encode("utf-8"))
            cipher_bits = ''.join(format(b, '08b') for b in cipher_bytes)
        except Exception:
            return None, ["Error: Input bukan Base64 valid DAN bukan rangkaian bit biner!"]

    plain_bits, log, seed = stream_cipher_process(cipher_bits, key, "dekripsi")

    try:
        plain_text = ''.join(chr(int(plain_bits[i:i+8], 2)) for i in range(0, len(plain_bits), 8))
        return plain_text, log
    except Exception as e:
        return None, [f"Error konversi bit ke teks: {e}"]


# =========================================================
# BLOCK CIPHER
BLOCK_SIZE_DEFAULT = 4

def block_cipher_pad(text, block_size):
    sisa = len(text) % block_size
    pad_len = block_size - sisa if sisa != 0 else block_size
    padded = text + chr(pad_len) * pad_len
    return padded, pad_len

def block_cipher_unpad(text):
    if not text:
        return text
    pad_len = ord(text[-1])
    if 0 < pad_len <= len(text):
        return text[:-pad_len]
    return text

def split_blocks(text, block_size):
    return [text[i:i + block_size] for i in range(0, len(text), block_size)]

def block_cipher_encrypt(text, key, block_size=BLOCK_SIZE_DEFAULT):
    log = []

    padded_text, pad_len = block_cipher_pad(text, block_size)
    log.append(f"[TAHAP 1] PADDING")
    log.append(f"  Panjang plaintext asli : {len(text)} karakter  ->  {text!r}")
    log.append(f"  Ukuran blok            : {block_size} karakter")
    log.append(f"  Jumlah padding dibutuhkan : {pad_len} karakter "
                f"(ditambahkan karakter chr({pad_len}) sebanyak {pad_len} kali)")
    log.append(f"  Plaintext setelah padding : {padded_text!r}  ({len(padded_text)} karakter)")
    log.append("")

    blocks = split_blocks(padded_text, block_size)
    log.append(f"[TAHAP 2] PEMBAGIAN MENJADI BLOK")
    log.append(f"  Total blok: {len(blocks)} (masing-masing {block_size} karakter)")
    for i, b in enumerate(blocks, start=1):
        log.append(f"    Blok {i}: {b!r}")
    log.append("")

    log.append(f"[TAHAP 3] ENKRIPSI TIAP BLOK  (rumus per karakter: (ord(char) + key) mod 256)")
    hasil_blocks = []
    for i, block in enumerate(blocks, start=1):
        log.append(f"  -- Blok {i} --  Input: {block!r}")
        cipher_block = ""
        for char in block:
            shifted_val = (ord(char) + key) % 256
            new_char = chr(shifted_val)
            log.append(f"     '{char}' (ord={ord(char)})  +  key({key})  mod 256  =  {shifted_val}  ->  '{new_char}'")
            cipher_block += new_char
        log.append(f"     Hasil Blok {i}: {cipher_block!r}")
        hasil_blocks.append(cipher_block)
    log.append("")

    result = "".join(hasil_blocks)
    log.append(f"[TAHAP 4] PENGGABUNGAN BLOK")
    log.append(f"  " + " + ".join(f"{b!r}" for b in hasil_blocks))
    log.append(f"  Ciphertext akhir: {result!r}")

    return result, log

def block_cipher_decrypt(cipher, key, block_size=BLOCK_SIZE_DEFAULT):
    log = []

    blocks = split_blocks(cipher, block_size)
    log.append(f"[TAHAP 1] PEMBAGIAN CIPHERTEXT MENJADI BLOK")
    log.append(f"  Panjang ciphertext : {len(cipher)} karakter  ->  {cipher!r}")
    log.append(f"  Ukuran blok        : {block_size} karakter, total {len(blocks)} blok")
    for i, b in enumerate(blocks, start=1):
        log.append(f"    Blok {i}: {b!r}")
    log.append("")

    log.append(f"[TAHAP 2] DEKRIPSI TIAP BLOK  (rumus per karakter: (ord(char) - key) mod 256)")
    hasil_blocks = []
    for i, block in enumerate(blocks, start=1):
        log.append(f"  -- Blok {i} --  Input: {block!r}")
        plain_block = ""
        for char in block:
            shifted_val = (ord(char) - key) % 256
            new_char = chr(shifted_val)
            log.append(f"     '{char}' (ord={ord(char)})  -  key({key})  mod 256  =  {shifted_val}  ->  '{new_char}'")
            plain_block += new_char
        log.append(f"     Hasil Blok {i}: {plain_block!r}")
        hasil_blocks.append(plain_block)
    log.append("")

    gabungan = "".join(hasil_blocks)
    log.append(f"[TAHAP 3] PENGGABUNGAN BLOK")
    log.append(f"  " + " + ".join(f"{b!r}" for b in hasil_blocks))
    log.append(f"  Hasil gabungan (masih ber-padding): {gabungan!r}")
    log.append("")

    plain_text = block_cipher_unpad(gabungan)
    pad_removed = len(gabungan) - len(plain_text)
    log.append(f"[TAHAP 4] UNPADDING")
    log.append(f"  Karakter terakhir menunjukkan {pad_removed} karakter padding -> dibuang")
    log.append(f"  Plaintext akhir: {plain_text!r}")

    return plain_text, log


# =========================================================
# SUPER ENKRIPSI
def super_encrypt(text, shift, vkey, skey, bkey=3, block_size=BLOCK_SIZE_DEFAULT):
    step1, log1 = caesar_enkripsi(text, shift)

    step2, vkey_ext2, vsteps2 = vigenere_enkripsi(step1, vkey)
    log2 = [f"{step1}", f"{vkey_ext2}", "Langkah:"] + vsteps2

    step3, log3, _raw_bits3 = stream_chiper_enkripsi(step2, skey)

    step4, log4 = block_cipher_encrypt(step3, bkey, block_size)

    stage_log = [
        ("Tahap 1 - Caesar Cipher", step1, log1),
        ("Tahap 2 - Vigenere Cipher", step2, log2),
        ("Tahap 3 - Stream Cipher (LFSR)", step3, log3),
        ("Tahap 4 - Block Cipher", step4, log4),
    ]
    return step4, stage_log

def super_decrypt(cipher, shift, vkey, skey, bkey=3, block_size=BLOCK_SIZE_DEFAULT):
    step1, log1 = block_cipher_decrypt(cipher, bkey, block_size)

    step2, log2 = stream_chiper_dekripsi(step1, skey)

    if step2 is None:
        stage_log = [
            ("Tahap 1 - Block Cipher (balik)", step1, log1),
            ("Tahap 2 - Stream Cipher (balik) - GAGAL", "(gagal didekripsi)", log2),
        ]
        return "[Gagal] Proses berhenti di tahap Stream Cipher — cek kembali kunci/ciphertext.", stage_log

    step3, vkey_ext3, vsteps3 = vigenere_dekripsi(step2, vkey)
    log3 = [f"{step2}", f"{vkey_ext3}", "Langkah:"] + vsteps3

    step4, log4 = caesar_dekripsi(step3, shift)

    stage_log = [
        ("Tahap 1 - Block Cipher (balik)", step1, log1),
        ("Tahap 2 - Stream Cipher (balik)", step2, log2),
        ("Tahap 3 - Vigenere Cipher (balik)", step3, log3),
        ("Tahap 4 - Caesar Cipher (balik)", step4, log4),
    ]
    return step4, stage_log


# =========================================================
# PAGE CONFIG + CUSTOM CSS
st.set_page_config(
    page_title="Aplikasi Kriptografi",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 1300px; }

    /* Judul gradient pink */
    h1 {
        background: linear-gradient(90deg, #EC4899, #F9A8D4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800 !important;
    }

    /* Kartu hasil — pink lembut */
    .result-card {
        background: linear-gradient(135deg, #FCE7F3 0%, #FDF2F8 100%);
        border-left: 5px solid #EC4899;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        margin: 0.5rem 0 1rem 0;
        font-family: 'Courier New', monospace;
        word-break: break-all;
        color: #831843;
    }
    .result-card .label {
        font-family: sans-serif;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #DB2777;
        font-weight: 700;
        margin-bottom: 0.3rem;
    }

    /* Tombol */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(236,72,153,0.30);
    }

    /* Sidebar pink tua */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #831843 0%, #BE185D 100%);
    }
    section[data-testid="stSidebar"] * { color: #FCE7F3 !important; }
    section[data-testid="stSidebar"] .stRadio label { color: #FCE7F3 !important; }

    /* Kartu identitas kelompok */
    .team-card {
        background: rgba(255, 255, 255, 0.10);
        border: 1px solid rgba(252, 231, 243, 0.30);
        border-radius: 12px;
        padding: 0.9rem 1rem;
        margin-top: 0.8rem;
    }
    .team-card h4 {
        margin: 0 0 0.6rem 0;
        font-size: 0.95rem;
        color: #FFFFFF !important;
        font-weight: 800;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.35);
    }
    .team-card ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    .team-card li {
        font-size: 0.9rem;
        padding: 0.35rem 0;
        border-bottom: 1px dashed rgba(255, 255, 255, 0.25);
        color: #FFFFFF !important;
        font-weight: 600;
        text-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
        letter-spacing: 0.2px;
    }
    .team-card li:last-child { border-bottom: none; }
    .team-card .num {
        display: inline-block;
        width: 20px;
        height: 20px;
        line-height: 20px;
        text-align: center;
        border-radius: 50%;
        background: #EC4899;
        color: #fff !important;
        font-size: 0.72rem;
        font-weight: 700;
        margin-right: 0.5rem;
    }

    /* Expander */
    div[data-testid="stExpander"] {
        border-radius: 10px;
        border: 1px solid #FBCFE8;
    }
    div[data-testid="stExpander"] pre {
        white-space: pre-wrap !important;
        word-break: break-word !important;
        font-size: 0.82rem !important;
        line-height: 1.45 !important;
    }

    hr { margin: 1rem 0 !important; }
</style>
""", unsafe_allow_html=True)

# =========================================================
# HELPER UNTUK MENAMPILKAN LOG & HASIL
def tampilkan_hasil(label: str, value: str):
    st.markdown(f"""
        <div class="result-card">
            <div class="label">{label}</div>
            <div>{value}</div>
        </div>
    """, unsafe_allow_html=True)
    st.code(value, language="text")

def tampilkan_log(log, judul="🔍 Lihat Proses"):
    with st.expander(judul, expanded=False):
        st.code("\n".join(log), language="text")

def tampilkan_log_vigenere(text, extended_key, steps, judul="🔍 Lihat Proses"):
    with st.expander(judul, expanded=False):
        st.code(f"{text}\n{extended_key}", language="text")
        st.markdown("**Langkah:**")
        st.code("\n".join(steps), language="text")

def tampilkan_log_super(stage_log, judul="🔍 Lihat Proses per Tahap"):
    with st.expander(judul, expanded=False):
        for nama_tahap, hasil_tahap, log_tahap in stage_log:
            st.markdown(f"**{nama_tahap}**")
            st.text(f"Hasil tahap ini: {hasil_tahap!r}")
            st.code("\n".join(log_tahap), language="text")
            st.divider()


# =========================================================
# HEADER + SIDEBAR
st.title("🔐 Aplikasi Kriptografi")
st.caption("Implementasi Caesar · Vigenere · Stream (LFSR) · Block Cipher")

MENU = {
    "Caesar Cipher": "Caesar Cipher",
    "Vigenere Cipher": "Vigenere Cipher",
    "Stream Cipher": "Stream Cipher",
    "Block Cipher": "Block Cipher",
    "Super Enkripsi": "Super Enkripsi",
}

KELAS = "Kriptografi IF-D"
ANGGOTA = [
    "Nayla Saskia Zallianti - 123240016",
    "Aulya Revalina - 123240141",
    "Azzah Fauziya Kamila - 123240168",
    "Chatarina Giftadiyana - 123240183",
]

with st.sidebar:
    st.markdown("### 📚 Pilih Algoritma")
    label = st.radio("Menu", list(MENU.keys()), label_visibility="collapsed")
    menu = MENU[label]

    st.divider()

    # --- Kartu Identitas Kelompok ---
    anggota_html = "".join(
        f'<li><span class="num">{i+1}</span>{nama}</li>'
        for i, nama in enumerate(ANGGOTA)
    )
    st.markdown(f"""
        <div class="team-card">
            <h4>{KELAS}</h4>
            <ul>{anggota_html}</ul>
        </div>
    """, unsafe_allow_html=True)


# =========================================================
# MENU: CAESAR CIPHER
if menu == "Caesar Cipher":
    st.header("Caesar Cipher")
    st.caption("Menggeser setiap huruf sejauh nilai shift pada alfabet.")

    with st.form("caesar_form"):
        c1, c2 = st.columns([3, 1])
        with c1:
            text = st.text_input("Teks / Ciphertext", placeholder="contoh: Halo Dunia")
        with c2:
            shift = st.number_input("Shift", 1, 25, 3)
        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
        submit = st.form_submit_button("Proses", type="primary", use_container_width=True)

    if submit:
        if not text:
            st.warning("⚠️ Teks tidak boleh kosong!")
        elif mode == "Enkripsi":
            hasil, log = caesar_enkripsi(text, shift)
            tampilkan_hasil("Ciphertext", hasil)
            tampilkan_log(log, "🔍 Lihat Proses Enkripsi")
        else:
            hasil, log = caesar_dekripsi(text, shift)
            tampilkan_hasil("Plaintext", hasil)
            tampilkan_log(log, "🔍 Lihat Proses Dekripsi")


# =========================================================
# MENU: VIGENERE CIPHER
elif menu == "Vigenere Cipher":
    st.header("Vigenere Cipher")
    st.caption("Enkripsi polyalphabetic menggunakan kunci huruf.")

    with st.form("vigenere_form"):
        text = st.text_input("Teks / Ciphertext", placeholder="contoh: Serang Fajar")
        key = st.text_input("Kunci", placeholder="contoh: informatika jaya")
        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
        submit = st.form_submit_button("Proses", type="primary", use_container_width=True)

    if submit:
        if not text or not key:
            st.warning("⚠️ Teks dan kunci harus diisi!")
        elif not any(c.isalpha() for c in key):
            st.warning("⚠️ Kunci harus mengandung minimal satu huruf!")
        else:
            if mode == "Enkripsi":
                hasil, ek, steps = vigenere_enkripsi(text, key)
                tampilkan_hasil("Ciphertext", hasil)
                tampilkan_log_vigenere(text, ek, steps, "🔍 Lihat Proses Enkripsi")
            else:
                hasil, ek, steps = vigenere_dekripsi(text, key)
                tampilkan_hasil("Plaintext", hasil)
                tampilkan_log_vigenere(text, ek, steps, "🔍 Lihat Proses Dekripsi")


# =========================================================
# MENU: STREAM CIPHER
elif menu == "Stream Cipher":
    st.header("Stream Cipher (LFSR Modern)")
    st.caption("Mode bitwise: Plaintext → Bit → XOR Keystream LFSR → Base64.")

    with st.form("stream_form"):
        input_text = st.text_area(
            "Input (Plaintext / Base64 / deretan bit 0101...)",
            height=120,
            placeholder="Masukkan teks biasa untuk enkripsi, atau Base64/bit untuk dekripsi",
        )
        key = st.text_input("Kunci", value="rahasia")
        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
        submit = st.form_submit_button("Proses", type="primary", use_container_width=True)

    if submit:
        if not input_text or not key:
            st.warning("⚠️ Input dan kunci harus diisi!")
        elif mode == "Enkripsi":
            b64, log, raw = stream_chiper_enkripsi(input_text, key)
            tampilkan_hasil("Ciphertext (Base64)", b64)
            st.info(f"**Raw Bit:** `{raw}`")
            tampilkan_log(log, "🔍 Tahapan Proses Enkripsi")
        else:
            plain, log = stream_chiper_dekripsi(input_text, key)
            if plain is not None:
                tampilkan_hasil("Plaintext", plain)
                tampilkan_log(log, "🔍 Tahapan Proses Dekripsi")
            else:
                st.error("Gagal mendekripsi!\n\n" + "\n".join(log))


# =========================================================
# MENU: BLOCK CIPHER
elif menu == "Block Cipher":
    st.header("Block Cipher")
    st.caption("Teks di-padding → dipecah per blok → tiap blok ditransformasi.")

    with st.form("block_form"):
        text = st.text_input("Teks / Ciphertext")
        c1, c2 = st.columns(2)
        with c1:
            key = st.number_input("Kunci pergeseran", 1, 255, 3)
        with c2:
            bs = st.number_input("Ukuran blok (karakter)", 2, 16, BLOCK_SIZE_DEFAULT)
        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
        submit = st.form_submit_button("Proses", type="primary", use_container_width=True)

    if submit:
        if not text:
            st.warning("⚠️ Teks tidak boleh kosong!")
        elif mode == "Enkripsi":
            hasil, log = block_cipher_encrypt(text, key, bs)
            tampilkan_hasil("Ciphertext", hasil)
            tampilkan_log(log, "🔍 Proses Enkripsi per Blok")
        else:
            if len(text) % bs != 0:
                st.error(f"⚠️ Panjang ciphertext ({len(text)}) harus kelipatan blok ({bs})!")
            else:
                hasil, log = block_cipher_decrypt(text, key, bs)
                tampilkan_hasil("Plaintext", hasil)
                tampilkan_log(log, "🔍 Proses Dekripsi per Blok")


# =========================================================
# MENU: SUPER ENKRIPSI
elif menu == "Super Enkripsi":
    st.header("Super Enkripsi")
    st.caption("Gabungan 4 lapis: Caesar → Vigenere → Stream → Block.")

    with st.form("super_form"):
        text = st.text_input("Teks / Ciphertext")

        st.markdown("**🔑 Kunci**")
        c1, c2, c3 = st.columns(3)
        with c1:
            shift = st.number_input("Shift Caesar", 1, 25, 3)
            vkey = st.text_input("Kunci Vigenere")
        with c2:
            skey = st.text_input("Kunci Stream", value="rahasia")
            bkey = st.number_input("Kunci Block", 1, 255, 3)
        with c3:
            bs = st.number_input("Ukuran blok", 2, 16, BLOCK_SIZE_DEFAULT)

        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True)
        submit = st.form_submit_button("Proses", type="primary", use_container_width=True)

    if submit:
        if not text or not vkey or not skey:
            st.warning("⚠️ Semua input (teks, vigenere key, stream key) harus diisi!")
        elif not any(c.isalpha() for c in vkey):
            st.warning("⚠️ Kunci Vigenere harus mengandung minimal satu huruf!")
        else:
            if mode == "Enkripsi":
                hasil, stage_log = super_encrypt(text, shift, vkey, skey, bkey, bs)
                tampilkan_hasil("Ciphertext (Super)", hasil)
                tampilkan_log_super(stage_log, "🔍 Proses Enkripsi per Tahap")
            else:
                hasil, stage_log = super_decrypt(text, shift, vkey, skey, bkey, bs)
                tampilkan_hasil("Plaintext (Super)", hasil)
                tampilkan_log_super(stage_log, "🔍 Proses Dekripsi per Tahap")