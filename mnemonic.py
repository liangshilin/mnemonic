#!/usr/bin/python3
# *_* coding= utf-8 *_*

import base64
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
def encrypt_mnemonic(mnemonic: str, password: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    token = f.encrypt(mnemonic.encode())
    print("encrypt_mnemonic: ")
    print(f"password: {password}")
    print(f"salt: {salt.hex()}")
    print(f"encrypt: {token.decode()}")
    print(f"mnemonic: {mnemonic}")

    return (token , salt)


def decrypt_mnemonic(token: str, salt_hex: str, password: str):
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    mnemonic = f.decrypt(token.encode())
    print("decrypt_mnemonic: ")
    print(f"password: {password}")
    print(f"salt: {salt.hex()}")
    print(f"encrypt: {token}")
    print(f"mnemonic: {mnemonic.decode()}")


if __name__ == "__main__":
    type = sys.argv[1]
    print(sys.argv)
    if type != "encrypt" and type != "decrypt":
        print("only support encrypt or decrypt")
    if type == "encrypt" and len(sys.argv) < 4:
        print("encrypt need mnemonic string and password")
    if type == "decrypt" and len(sys.argv) < 5:
        print("decrypt need taken str, salt hex str and password")

    if type == "encrypt":
        encrypt_mnemonic(sys.argv[2], sys.argv[3])
    elif type == "decrypt":
        decrypt_mnemonic(sys.argv[2], sys.argv[3], sys.argv[4])

    # mnemonic_str = sys.argv[1]
    # token, salt = encrypt_mnemonic("1111,2222,3333,4444,5555,6666,7777,8888,9999", "shilin123")
    # decrypt_mnemonic(token.decode(), salt.hex(), "shilin123")
    exit(0)


