import gnupg
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

## Generating RSA keys for PIP (currently acting as a Source of Authority for the access rights) - Different from GPG keys
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
        "aud": "pip"
    }

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
print("key id: ", key)
print("PGP unique identifier (fingerprint): ", key.fingerprint)

'''public_key = gpg.export_keys(key.fingerprint)
print("Public key: ", public_key)

private_key = gpg.export_keys(key.fingerprint, True, passphrase="123456")
print("Private_key: ", private_key)

signing = gpg.sign(
    "This message is signed",
    keyid = key.fingerprint,
    passphrase = "123456"
)
print("signed data: ", str(signing))

encrypt = gpg.encrypt(
    "Vir is amazing",
    recipients=[key.fingerprint]
)
print("encrypted message: ", str(encrypt))

decrypt = gpg.decrypt(str(encrypt), passphrase = "123456")
print("decrypted message: ", decrypt.data.decode())'''

print()
print()

keys = gpg.list_keys()
#print(keys)

for key in keys:
    for uid in key['uids']:
        print(uid)
    print(key['type'])

'''for key in keys:
    gpg.delete_keys(key['fingerprint'], secret=True, passphrase = "123456")
    gpg.delete_keys(key['fingerprint'])'''

'''# Generating Extra Names without generating a new key:
# Fingerprint of the key you want to modify
key_fingerprint = 'YOUR_KEY_FINGERPRINT_HERE'

# Define the new user ID
new_user_id = 'New Name <new.email@example.com>'

# Commands to send to GPG
# 'adduid' initiates the process, followed by the new ID, 'save', and 'quit'
cmd = f'adduid\n{new_user_id}\n\n1\nsave\nquit'

# Use edit_key with extra arguments to send the commands
result = gpg.submit_keys(key_fingerprint, cmd)

print(result.status)'''