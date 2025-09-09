# Copyright (c) 2025 iiPython

# Modules
from pathlib import Path
from nacl.public import Box, PrivateKey, PublicKey

from radon.utils.encoding import encode, decode

# Initialization
RADON_FOLDER = Path.home() / ".local/share/radon"

def fetch_keys(filename: str = "pk.bin") -> tuple[PrivateKey, str]:
    private_key_file = RADON_FOLDER / filename
    if private_key_file.is_file():
        private_key = PrivateKey(private_key_file.read_bytes())

    else:   
        private_key = PrivateKey.generate()

        private_key_file.parent.mkdir(parents = True, exist_ok = True)
        private_key_file.write_bytes(bytes(private_key))

    return (
        private_key,
        encode(bytes(private_key.public_key))
    )

# Handle encryption/decryption
def encrypt(private: PrivateKey, target: bytes, message: str) -> str:
    return encode(bytes(Box(private, PublicKey(target)).encrypt(message.encode())))

def decrypt(private: PrivateKey, sender: bytes, message: str) -> str:
    return Box(private, PublicKey(sender)).decrypt(decode(message)).decode()

