
# Certificate Generator
# Generates the PGP certificate in compatibly format with PIP by adding the attributes as a JWT

import gnupg
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generating RSA keys for PIP (currently acting as a Source of Authority for the access rights) - Different from GPG keys
# Acts as trust anchor to be able to encrypt and send JWT to PDP and PDP can verify
# Need to convert the keys into PEM format as JWT only recogises that format and cannot directly use the key.

SoA_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SoA_public_key = SoA_private_key.public_key()

SoA_private_pem = SoA_private_key.private_bytes( #pem format of private key
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() #No encryption as JWT needs string
)

SoA_public_pem = SoA_public_key.public_bytes( #pem version of public key
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Writing the pems to a .pem so can be accessed by PIP later from these files
with open("SoA_private_pem.pem","wb") as f:
    f.write(SoA_private_pem)

with open("SoA_public_pem.pem","wb") as f:
    f.write(SoA_public_pem)

def create_jwt(token_subject, attributes, private_key_pem):
    payload = {
        "sub": token_subject,
        "iss": "SoA", #issuer
        "iat": int(time.time()), #issued at time
        "expiry": int(time.time() + 3600), #Expiry time, set to 60 minutes from issuing
        "aud": "pip" #Audience set to pip so only the pip having the same aud can access
    }

    # Adding the attributes to the payload of the JWT
    payload.update(attributes)

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    return token

# Creating pgp certificate using gpg and jwt

gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
                options=["--pinentry-mode", "loopback"])

input_data = gpg.gen_key_input(
    name_real = 'SOA',
    name_email = "test@example.com",
    key_type="RSA", 
    key_length=2048,
    passphrase = "123456",
    name_comment= create_jwt('attribute_token',{"role":"employee","department":"admin"},SoA_private_pem),
    expire_date= "1d",
    )

key = gpg.gen_key(input_data)

print(input_data)
print("PGP unique identifier (fingerprint): ", key.fingerprint)

print()
print()

keys = gpg.list_keys()
#print(keys)

# Print out all the UIDs of all keys in the GnuPGHome
for key in keys:
    for uid in key['uids']:
        print(uid)
    print(key['type'])

# Code for deleting all keys in the GnuPGHome
'''for key in keys:
    gpg.delete_keys(key['fingerprint'], secret=True, passphrase = "123456")
    gpg.delete_keys(key['fingerprint'])'''
