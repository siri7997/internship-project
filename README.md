# internship-project
StegImage - LSB Steganography Tool

A steganography utility for hiding text or files inside images using LSB (least-significant bit) technique. This tool supports both command-line interface (CLI) and GUI (if tkinter is available).

Features

Embed text into images.

Embed files into images.

Extract hidden text or files from images.

Password-protected encryption (AES via PyCryptodome if installed; XOR fallback otherwise).

Image capacity check to see how much data can be hidden.

Optional GUI interface with drag-and-drop support.

Built-in unit-style tests for embedding/extraction with/without password.

Technical Details

LSB Steganography: Hides payload data in the least significant bits of the image’s RGB channels.

Container format:

Header contains a magic value, version, flags, payload length, and optional filename.

Payload can be encrypted.

Encryption:

AES-CBC (requires PyCryptodome) for secure encryption.

XOR-derived keystream as fallback if AES is unavailable.

Python Libraries:

Required: Pillow for image handling.

Optional: PyCryptodome for AES encryption.

Optional (GUI only): tkinter, tkinterdnd2.

Usage Examples (CLI)

Embed text into an image:

python steg_gui.py embed-text --cover cover.png --out stego.png --text "secret message"


Embed a file with password protection:

python steg_gui.py embed-file --cover cover.png --out stego.png --file secret.zip --password hunter2


Extract hidden data:

python steg_gui.py extract --stego stego.png --out extracted.txt --password hunter2


Check image capacity:

python steg_gui.py capacity --cover cover.png


Run built-in tests:

python steg_gui.py --test


Launch GUI (if tkinter available):

python steg_gui.py --gui

Security Note

AES encryption is strong and recommended.

XOR fallback is not secure; only for environments without PyCryptodome.

Always use a password for sensitive data.

Installation
pip install Pillow
pip install pycryptodome  # optional for AES encryption
pip install tkinterdnd2   # optional, for drag-and-drop in GUI

Limitations

LSB steganography is not resistant to image compression (e.g., JPEG).

Image must be large enough to hold the payload.

XOR fallback encryption is not secure.
