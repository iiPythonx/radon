# Copyright (c) 2025 iiPython

# Modules
from pathlib import Path
from nacl.public import Box, PrivateKey, PublicKey

from radon.utils.encoding import encode, decode

# Initialization
PRIVATE_KEY_FILE = Path.home() / ".local/share/radon/pk.bin"
if PRIVATE_KEY_FILE.is_file():
    PRIVATE_KEY = PrivateKey(PRIVATE_KEY_FILE.read_bytes())

else:   
    PRIVATE_KEY = PrivateKey.generate()

    PRIVATE_KEY_FILE.parent.mkdir(parents = True, exist_ok = True)
    PRIVATE_KEY_FILE.write_bytes(bytes(PRIVATE_KEY))

PUBLIC_KEY = encode(bytes(PRIVATE_KEY.public_key))

# Handle encryption/decryption
def encrypt(target: bytes, message: str) -> str:
    return encode(bytes(Box(PRIVATE_KEY, PublicKey(target)).encrypt(message.encode())))

def decrypt(sender: bytes, message: str) -> str:
    return Box(PRIVATE_KEY, PublicKey(sender)).decrypt(decode(message)).decode()

