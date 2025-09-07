"""
steg_gui.py

A single-file steganography utility for embedding/extracting text or files into/from images using LSB (least-significant bit).

This file was originally a tkinter GUI application. Some execution environments (including the one you ran
in) do not provide the `tkinter` module, which raises `ModuleNotFoundError: No module named 'tkinter'`.

This rewritten script detects whether `tkinter` is available. If it is, the GUI is available (mostly the same
features). If `tkinter` is not present, the script gracefully falls back to a command-line interface (CLI)
that supports the same operations: embed-text, embed-file, extract, capacity and tests.

Key fixes and improvements over the original:
- Do NOT import tkinter at top-level unguarded; import it only if available.
- Header is built *after* encryption so `payload_len` in the header matches the final stored bytes.
- Embedding now only modifies as many LSBs as needed and leaves the remainder of the image unchanged.
- Robust capacity checks and clearer error messages.
- CLI implemented with argparse so the tool works in environments without GUI support.
- A `--test` command generates test images and runs unit-style checks (embedding/extraction, with and without password).

Dependencies:
- Required: Pillow (`pip install Pillow`)
- Optional (recommended for real encryption): PyCryptodome (`pip install pycryptodome`) — provides AES.
- Optional (GUI only): tkinter (usually included with standard Python builds) and tkinterdnd2 for drag-and-drop.

Usage examples (CLI):
  python steg_gui.py embed-text --cover cover.png --out stego.png --text "secret message"
  python steg_gui.py embed-file --cover cover.png --out stego.png --file secret.zip --password hunter2
  python steg_gui.py extract --stego stego.png --out extracted.txt
  python steg_gui.py capacity --cover cover.png
  python steg_gui.py --gui        # start GUI if tkinter available
  python steg_gui.py --test       # run built-in tests

Security note: AES via PyCryptodome is used if available. Otherwise the script uses a simple XOR-derived keystream as a fallback — this is NOT cryptographically strong. Install `pycryptodome` for proper encryption.

This tool is for educational and legitimate use only.
"""

import os
import struct
import sys
import math
import io
import hashlib
import argparse
import tempfile
import getpass

try:
    from PIL import Image
except Exception:
    raise SystemExit('Pillow is required. Install it with: pip install Pillow')

# Optional AES support (PyCryptodome)
USE_AES = False
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    USE_AES = True
except Exception:
    USE_AES = False

# Optional tkinter GUI support; import only if available.
USE_TKINTER = False
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
    from tkinter import scrolledtext
    USE_TKINTER = True
except Exception:
    USE_TKINTER = False

# Optional drag-and-drop (GUI only)
USE_DND = False
if USE_TKINTER:
    try:
        import tkinterdnd2
        USE_DND = True
    except Exception:
        USE_DND = False

MAGIC = b'STEG'  # 4 bytes magic
VERSION = 1
# Header layout (little-endian):
# 4s   MAGIC
# B    version
# B    flags (bit0: is_file, bit1: encrypted)
# I    payload length (bytes)
# H    filename length (if is_file)
# ...  filename (utf-8)
# Then payload bytes

HEADER_FMT = '<4sB B I H'  # magic, version, flags, payload_len, filename_len
HEADER_SIZE_FIXED = struct.calcsize(HEADER_FMT)

SALT = b'steg_salt_v1'  # fixed salt (small simplification)

# ------------------------- Crypto helpers -------------------------

def derive_key(password: str, length=32):
    """Derive a key from password. If PBKDF2 is available use it, otherwise use repeated sha512 hashing.
    """
    if not password:
        return b'\x00' * length
    if USE_AES:
        return PBKDF2(password, SALT, dkLen=length, count=100000)
    else:
        h = password.encode('utf8') + SALT
        key = hashlib.sha512(h).digest()
        while len(key) < length:
            key = hashlib.sha512(key).digest() + key
        return key[:length]


def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        return data
    key = derive_key(password, 32)
    if USE_AES:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = 16 - (len(data) % 16)
        data_padded = data + bytes([pad_len]) * pad_len
        ct = cipher.encrypt(data_padded)
        return iv + ct
    else:
        keystream = hashlib.sha256(key).digest()
        out = bytearray()
        kslen = len(keystream)
        for i, b in enumerate(data):
            out.append(b ^ keystream[i % kslen])
        return bytes(out)


def decrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        return data
    key = derive_key(password, 32)
    if USE_AES:
        if len(data) < 16:
            raise ValueError('Encrypted data too short to contain IV')
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt_padded = cipher.decrypt(ct)
        pad_len = pt_padded[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError('Bad padding (wrong password?)')
        return pt_padded[:-pad_len]
    else:
        keystream = hashlib.sha256(key).digest()
        out = bytearray()
        kslen = len(keystream)
        for i, b in enumerate(data):
            out.append(b ^ keystream[i % kslen])
        return bytes(out)

# ------------------------- Bit helpers -------------------------

def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def _bits_to_bytes(bits):
    b = bytearray()
    cur = 0
    count = 0
    for bit in bits:
        cur = (cur << 1) | (1 if bit else 0)
        count += 1
        if count == 8:
            b.append(cur & 0xFF)
            cur = 0
            count = 0
    return bytes(b)

# ------------------------- Steg container builders -------------------------

def make_container(payload_bytes: bytes, is_file=False, filename: str = '', encrypted: bool = False) -> bytes:
    """Build the on-disk container: header + filename (if any) + payload bytes.

    The payload_bytes should already be encrypted if encrypted==True.
    """
    fname_b = filename.encode('utf8') if filename else b''
    flags = 0
    if is_file:
        flags |= 1
    if encrypted:
        flags |= 2
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, flags, len(payload_bytes), len(fname_b))
    return header + fname_b + payload_bytes

# ------------------------- Image helpers -------------------------

def capacity_bytes_for_image(img: Image.Image) -> int:
    # number of available LSBs: width*height*channels (we use RGB => 3 channels)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    w, h = img.size
    channels = 3  # use R,G,B
    return (w * h * channels) // 8  # bytes


def embed_bytes_into_image(cover_path: str, out_path: str, data: bytes):
    img = Image.open(cover_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    w, h = img.size
    pixels = list(img.getdata())

    bits = list(_bytes_to_bits(data))
    total_available_bits = w * h * 3
    if len(bits) > total_available_bits:
        raise ValueError(f'Payload too large: need {len(bits)} bits but image has {total_available_bits} bits')

    new_pixels = []
    bit_idx = 0
    for pix in pixels:
        r, g, b = pix[0], pix[1], pix[2]
        if bit_idx < len(bits):
            r = (r & ~1) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | bits[bit_idx]
            bit_idx += 1
        if len(pix) == 4:
            new_pixels.append((r, g, b, pix[3]))
        else:
            new_pixels.append((r, g, b))
    # If we didn't modify some trailing pixels (because payload ended), keep the rest original (new_pixels already contains them)
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(out_path)


def extract_bytes_from_image(stego_path: str) -> dict:
    img = Image.open(stego_path)
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGBA')
    pixels = list(img.getdata())

    bits = []
    for pix in pixels:
        bits.append(pix[0] & 1)
        bits.append(pix[1] & 1)
        bits.append(pix[2] & 1)

    if len(bits) < HEADER_SIZE_FIXED * 8:
        raise ValueError('Image too small or not a STEG file (no header)')

    header_bits = bits[:HEADER_SIZE_FIXED * 8]
    header_bytes = _bits_to_bytes(header_bits)
    try:
        magic, version, flags, payload_len, fname_len = struct.unpack(HEADER_FMT, header_bytes)
    except Exception:
        raise ValueError('No valid STEG header found')
    if magic != MAGIC:
        raise ValueError('Bad magic (not a STEG file)')

    # read filename
    start = HEADER_SIZE_FIXED * 8
    fname_bits = bits[start:start + fname_len * 8]
    if len(fname_bits) < fname_len * 8:
        raise ValueError('Filename truncated')
    fname_bytes = _bits_to_bytes(fname_bits)
    filename = fname_bytes.decode('utf8') if fname_len else ''

    # read payload
    start_payload = start + (fname_len * 8)
    payload_bits = bits[start_payload:start_payload + payload_len * 8]
    if len(payload_bits) < payload_len * 8:
        raise ValueError('Payload truncated')
    payload_bytes = _bits_to_bytes(payload_bits)

    is_file = bool(flags & 1)
    encrypted = bool(flags & 2)

    return {'filename': filename, 'is_file': is_file, 'encrypted': encrypted, 'payload': payload_bytes}

# ------------------------- CLI Implementation -------------------------

def cli_embed_text(cover, out, text, password=None):
    data = text.encode('utf8')
    encrypted = False
    body = data
    if password:
        body = encrypt_bytes(body, password)
        encrypted = True
    container = make_container(body, is_file=False, filename='', encrypted=encrypted)
    img = Image.open(cover)
    cap = capacity_bytes_for_image(img)
    if len(container) > cap:
        raise ValueError(f'Payload too large for this image. Capacity {cap} bytes, payload {len(container)} bytes')
    embed_bytes_into_image(cover, out, container)
    print(f'Embedded text into {out} (was encrypted={encrypted})')


def cli_embed_file(cover, out, file_to_hide, password=None):
    with open(file_to_hide, 'rb') as f:
        content = f.read()
    filename = os.path.basename(file_to_hide)
    encrypted = False
    body = content
    if password:
        body = encrypt_bytes(body, password)
        encrypted = True
    container = make_container(body, is_file=True, filename=filename, encrypted=encrypted)
    img = Image.open(cover)
    cap = capacity_bytes_for_image(img)
    if len(container) > cap:
        raise ValueError(f'Payload too large for this image. Capacity {cap} bytes, payload {len(container)} bytes')
    embed_bytes_into_image(cover, out, container)
    print(f'Embedded file "{filename}" into {out} (was encrypted={encrypted})')


def cli_extract(stego, out=None, password=None):
    res = extract_bytes_from_image(stego)
    payload = res['payload']
    if res['encrypted']:
        if not password:
            password = getpass.getpass('Password to decrypt payload: ')
        payload = decrypt_bytes(payload, password)
    if res['is_file']:
        suggested = res['filename'] or 'extracted.bin'
        savep = out or suggested
        # avoid overwrite unless explicitly specified
        if os.path.exists(savep):
            base, ext = os.path.splitext(savep)
            i = 1
            while os.path.exists(savep):
                savep = f"{base}_{i}{ext}"
                i += 1
        with open(savep, 'wb') as f:
            f.write(payload)
        print(f'Extracted file saved to {savep}')
    else:
        try:
            text = payload.decode('utf8')
        except Exception:
            text = None
        if out:
            # write raw bytes
            with open(out, 'wb') as f:
                f.write(payload)
            print(f'Extracted payload written to {out}')
        else:
            if text is not None:
                print('--- Extracted text start ---')
                print(text)
                print('--- Extracted text end ---')
            else:
                print('Extracted non-text payload (binary). Use --out to save to file.')


def cli_capacity(cover):
    img = Image.open(cover)
    cap = capacity_bytes_for_image(img)
    print(f'Image capacity: approximately {cap} bytes')

# ------------------------- GUI Implementation (optional) -------------------------

if USE_TKINTER:
    class StegApp:
        def __init__(self, root):
            self.root = root
            root.title('StegImage - LSB Steganography (embed & extract)')
            self.cover_path = tk.StringVar()
            self.output_path = tk.StringVar()
            self.embed_mode = tk.StringVar(value='text')  # 'text' or 'file'
            self.password = tk.StringVar()
            self.use_password = tk.BooleanVar(value=False)
            self.status = tk.StringVar()

            self._build_ui()

        def _build_ui(self):
            frm = tk.Frame(self.root, padx=8, pady=8)
            frm.pack(fill='both', expand=True)

            # Cover image
            top = tk.Frame(frm)
            top.pack(fill='x')
            tk.Label(top, text='Cover image:').pack(side='left')
            tk.Entry(top, textvariable=self.cover_path, width=50).pack(side='left', padx=6)
            tk.Button(top, text='Browse...', command=self.browse_cover).pack(side='left')

            if USE_DND:
                tk.Label(frm, text='(Drag & drop supported)') .pack(anchor='w')

            # Embed options
            opt = tk.Frame(frm)
            opt.pack(fill='x', pady=6)
            tk.Radiobutton(opt, text='Embed text', variable=self.embed_mode, value='text').pack(side='left')
            tk.Radiobutton(opt, text='Embed file', variable=self.embed_mode, value='file').pack(side='left', padx=8)

            # Text area / file chooser
            self.text_area = scrolledtext.ScrolledText(frm, height=8)
            self.text_area.pack(fill='both', expand=True)

            file_row = tk.Frame(frm)
            file_row.pack(fill='x', pady=4)
            tk.Label(file_row, text='File to hide:').pack(side='left')
            self.hidden_file_entry = tk.Entry(file_row, width=50)
            self.hidden_file_entry.pack(side='left', padx=6)
            tk.Button(file_row, text='Browse...', command=self.browse_hidden_file).pack(side='left')

            # Password
            pass_row = tk.Frame(frm)
            pass_row.pack(fill='x', pady=6)
            tk.Checkbutton(pass_row, text='Use password (encrypt payload)', variable=self.use_password).pack(side='left')
            tk.Entry(pass_row, textvariable=self.password, show='*', width=30).pack(side='left', padx=6)
            if USE_AES:
                tk.Label(pass_row, text='(AES available)').pack(side='left')
            else:
                tk.Label(pass_row, text='(Using XOR fallback if password used)').pack(side='left')

            # Output
            out_row = tk.Frame(frm)
            out_row.pack(fill='x', pady=6)
            tk.Label(out_row, text='Output stego image:').pack(side='left')
            tk.Entry(out_row, textvariable=self.output_path, width=40).pack(side='left', padx=6)
            tk.Button(out_row, text='Save as...', command=self.save_stego_as).pack(side='left')

            # Buttons
            btn_row = tk.Frame(frm)
            btn_row.pack(fill='x', pady=8)
            tk.Button(btn_row, text='Embed ->', command=self.embed_action).pack(side='left')
            tk.Button(btn_row, text='<- Extract', command=self.extract_action).pack(side='left', padx=8)
            tk.Button(btn_row, text='Show capacity', command=self.show_capacity).pack(side='left')

            # Status
            status_row = tk.Frame(frm)
            status_row.pack(fill='x', pady=6)
            tk.Label(status_row, textvariable=self.status).pack(anchor='w')
            self.status.set('Ready')

        def browse_cover(self):
            p = filedialog.askopenfilename(title='Select cover image', filetypes=[('Images','*.png;*.bmp;*.tif;*.tiff;*.jpg;*.jpeg'), ('All files','*.*')])
            if p:
                self.cover_path.set(p)
                base, ext = os.path.splitext(p)
                self.output_path.set(base + '_stego' + ('.png' if ext.lower() not in ('.png', '.bmp') else ext))

        def browse_hidden_file(self):
            p = filedialog.askopenfilename(title='Select file to hide', filetypes=[('All files','*.*')])
            if p:
                self.hidden_file_entry.delete(0,'end')
                self.hidden_file_entry.insert(0,p)

        def save_stego_as(self):
            p = filedialog.asksaveasfilename(title='Save stego image as', defaultextension='.png', filetypes=[('PNG','*.png'),('BMP','*.bmp'),('TIFF','*.tif;*.tiff'),('All files','*.*')])
            if p:
                self.output_path.set(p)

        def show_capacity(self):
            p = self.cover_path.get()
            if not p or not os.path.exists(p):
                messagebox.showinfo('Capacity', 'Select a valid cover image first')
                return
            img = Image.open(p)
            cap = capacity_bytes_for_image(img)
            messagebox.showinfo('Capacity', f'Image can hide approximately {cap} bytes (text or file)')

        def embed_action(self):
            try:
                cover = self.cover_path.get()
                outp = self.output_path.get()
                if not cover or not os.path.exists(cover):
                    messagebox.showerror('Error', 'Select a valid cover image')
                    return
                if not outp:
                    messagebox.showerror('Error', 'Select output filename for stego image')
                    return
                mode = self.embed_mode.get()
                password = self.password.get() if self.use_password.get() else None
                if mode == 'text':
                    text = self.text_area.get('1.0','end').encode('utf8')
                    body = text
                    encrypted = False
                    if password:
                        body = encrypt_bytes(body, password)
                        encrypted = True
                    container = make_container(body, is_file=False, filename='', encrypted=encrypted)
                else:
                    fname = self.hidden_file_entry.get()
                    if not fname or not os.path.exists(fname):
                        messagebox.showerror('Error', 'Select a valid file to hide')
                        return
                    with open(fname, 'rb') as f:
                        content = f.read()
                    filename = os.path.basename(fname)
                    body = content
                    encrypted = False
                    if password:
                        body = encrypt_bytes(body, password)
                        encrypted = True
                    container = make_container(body, is_file=True, filename=filename, encrypted=encrypted)

                img = Image.open(cover)
                cap = capacity_bytes_for_image(img)
                if len(container) > cap:
                    messagebox.showerror('Error', f'Payload too large for this image. Capacity {cap} bytes, payload {len(container)} bytes')
                    return
                embed_bytes_into_image(cover, outp, container)
                self.status.set(f'Embedded successfully -> {outp}')
                messagebox.showinfo('Done', f'Payload embedded into {outp}')
            except Exception as e:
                messagebox.showerror('Error', f'Embedding failed: {e}')
                self.status.set('Error during embedding')

        def extract_action(self):
            try:
                p = self.cover_path.get()
                if not p or not os.path.exists(p):
                    messagebox.showerror('Error', 'Select a valid stego image to extract from (use the Cover image field)')
                    return
                res = extract_bytes_from_image(p)
                payload = res['payload']
                if res['encrypted']:
                    password = None
                    if self.use_password.get() and self.password.get():
                        password = self.password.get()
                    else:
                        password = simpledialog.askstring('Password required', 'Enter password to decrypt payload:', show='*')
                        if password is None:
                            return
                    payload = decrypt_bytes(payload, password)
                if res['is_file']:
                    suggested = res['filename'] or 'extracted.bin'
                    savep = filedialog.asksaveasfilename(title='Save extracted file as', initialfile=suggested)
                    if not savep:
                        return
                    with open(savep, 'wb') as f:
                        f.write(payload)
                    messagebox.showinfo('Done', f'Extracted file saved to {savep}')
                    self.status.set(f'Extracted file saved to {savep}')
                else:
                    try:
                        text = payload.decode('utf8')
                    except Exception:
                        text = repr(payload)
                    top = tk.Toplevel(self.root)
                    top.title('Extracted text')
                    txt = scrolledtext.ScrolledText(top, width=80, height=20)
                    txt.pack(fill='both', expand=True)
                    txt.insert('1.0', text)
                    tk.Button(top, text='Close', command=top.destroy).pack()
                    self.status.set('Extracted text displayed')
            except Exception as e:
                messagebox.showerror('Error', f'Extraction failed: {e}')
                self.status.set('Error during extraction')

# ------------------------- Tests -------------------------

def run_tests():
    print('Running built-in tests...')
    # Create a small cover image
    w, h = 64, 64
    cover_path = os.path.join(tempfile.gettempdir(), 'steg_test_cover.png')
    img = Image.new('RGBA', (w, h), color=(120, 200, 150, 255))
    img.save(cover_path)

    # Test 1: embed/extract text, no password
    out1 = os.path.join(tempfile.gettempdir(), 'steg_test_out1.png')
    secret = 'Hello, steg! \u2603'
    cli_embed_text(cover_path, out1, secret, password=None)
    res = extract_bytes_from_image(out1)
    assert not res['is_file']
    assert not res['encrypted']
    txt = res['payload'].decode('utf8')
    assert txt == secret.encode('utf8').decode('utf8') or txt == secret
    print('Test 1 passed (embed/extract text without password)')

    # Test 2: embed/extract file, no password
    sample_file = os.path.join(tempfile.gettempdir(), 'steg_test_sample.bin')
    with open(sample_file, 'wb') as f:
        f.write(b"\x00\x01\x02TESTBYTES\xFF\xFE")
    out2 = os.path.join(tempfile.gettempdir(), 'steg_test_out2.png')
    cli_embed_file(cover_path, out2, sample_file, password=None)
    res2 = extract_bytes_from_image(out2)
    assert res2['is_file']
    assert not res2['encrypted']
    assert res2['payload'] == open(sample_file, 'rb').read()
    print('Test 2 passed (embed/extract file without password)')

    # Test 3: embed/extract text with password
    out3 = os.path.join(tempfile.gettempdir(), 'steg_test_out3.png')
    secret2 = 'TopSecret123!'
    cli_embed_text(cover_path, out3, secret2, password='pw123')
    res3 = extract_bytes_from_image(out3)
    assert res3['encrypted']
    decrypted = decrypt_bytes(res3['payload'], 'pw123')
    assert decrypted.decode('utf8') == secret2
    print('Test 3 passed (embed/extract text with password)')

    # Test 4: capacity check (should be > small number)
    cap = capacity_bytes_for_image(Image.open(cover_path))
    assert cap > 0
    print('Test 4 passed (capacity > 0)')

    print('All tests passed! Temporary files are in:', tempfile.gettempdir())

# ------------------------- CLI Entrypoint -------------------------

def main():
    parser = argparse.ArgumentParser(description='LSB Steganography tool (embed/extract in images)')
    sub = parser.add_subparsers(dest='command')

    # embed-text
    p_embed_text = sub.add_parser('embed-text', help='Embed a text string into an image')
    p_embed_text.add_argument('--cover', required=True, help='Cover image path')
    p_embed_text.add_argument('--out', required=True, help='Output stego image path')
    p_embed_text.add_argument('--text', help='Text to embed (if omitted, read from stdin)')
    p_embed_text.add_argument('--password', help='Optional password to encrypt payload')

    # embed-file
    p_embed_file = sub.add_parser('embed-file', help='Embed an arbitrary file into an image')
    p_embed_file.add_argument('--cover', required=True, help='Cover image path')
    p_embed_file.add_argument('--out', required=True, help='Output stego image path')
    p_embed_file.add_argument('--file', required=True, help='File to hide')
    p_embed_file.add_argument('--password', help='Optional password to encrypt payload')

    # extract
    p_extract = sub.add_parser('extract', help='Extract payload from stego image')
    p_extract.add_argument('--stego', required=True, help='Stego image path')
    p_extract.add_argument('--out', help='Output path (for file or raw write). For text, prints to stdout if not provided')
    p_extract.add_argument('--password', help='Password to decrypt payload (if needed)')

    # capacity
    p_cap = sub.add_parser('capacity', help='Show capacity of a cover image')
    p_cap.add_argument('--cover', required=True, help='Cover image path')

    parser.add_argument('--test', action='store_true', help='Run built-in tests and exit')
    parser.add_argument('--gui', action='store_true', help='Launch GUI (only if tkinter available)')

    args = parser.parse_args()

    if args.test:
        run_tests()
        return

    # GUI requested
    if args.gui:
        if not USE_TKINTER:
            print('tkinter is not available in this environment. GUI cannot be started. Use CLI mode instead.')
            return
        root = tk.Tk()
        app = StegApp(root)
        root.mainloop()
        return

    if args.command == 'embed-text':
        text = args.text
        if text is None:
            print('Enter text to embed; finish with EOF (Ctrl-D / Ctrl-Z):')
            text = sys.stdin.read()
        try:
            cli_embed_text(args.cover, args.out, text, password=args.password)
        except Exception as e:
            print('Error:', e)
            sys.exit(2)
        return

    if args.command == 'embed-file':
        try:
            cli_embed_file(args.cover, args.out, args.file, password=args.password)
        except Exception as e:
            print('Error:', e)
            sys.exit(2)
        return

    if args.command == 'extract':
        try:
            cli_extract(args.stego, out=args.out, password=args.password)
        except Exception as e:
            print('Error:', e)
            sys.exit(2)
        return

    if args.command == 'capacity':
        try:
            cli_capacity(args.cover)
        except Exception as e:
            print('Error:', e)
            sys.exit(2)
        return

    # No command — if tkinter available launch GUI, otherwise show help
    if USE_TKINTER:
        root = tk.Tk()
        app = StegApp(root)
        root.mainloop()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
