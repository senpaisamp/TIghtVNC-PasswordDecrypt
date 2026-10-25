#!/usr/bin/env python3

from Crypto.Cipher import DES

MAGIC_KEY = bytes.fromhex("E8 4A D6 60 C4 72 1A E0")
ENCODING = "cp1252"


def convert_to_encrypted_vnc_password(password: str) -> bytes:
    """Encode in the DES VNC format at 8 byte."""
    password_bytes = password.encode(ENCODING)

    if len(password_bytes) > 8:
        raise ValueError("Password must not exceed 8 bytes")

    plaintext = password_bytes.ljust(8, b"\x00")
    cipher = DES.new(MAGIC_KEY, DES.MODE_ECB)

    return cipher.encrypt(plaintext)


def convert_from_encrypted_vnc_password(
    encrypted_data: bytes,
) -> str:
    """Decrypt a VNC password with the DES to 8 byte format."""
    if len(encrypted_data) != 8:
        raise ValueError("Encrypted data must be 8 bytes long")

    cipher = DES.new(MAGIC_KEY, DES.MODE_ECB)
    plaintext = cipher.decrypt(encrypted_data)

    return plaintext.rstrip(b"\x00").decode(ENCODING)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert VNC passwords using legacy DES."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", metavar="PASSWORD")
    group.add_argument("--decrypt", metavar="HEX")

    args = parser.parse_args()

    if args.encrypt is not None:
        encrypted = convert_to_encrypted_vnc_password(args.encrypt)
        print(encrypted.hex().upper())
    else:
        try:
            encrypted = bytes.fromhex(args.decrypt)
            password = convert_from_encrypted_vnc_password(encrypted)
            print(password)
        except ValueError as exc:
            parser.error(str(exc))

