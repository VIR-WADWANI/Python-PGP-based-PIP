import gnupg
import re
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

## Generating RSA keys for PIP (currently acting as a Source of Authority for the access rights) - Different from GPG keys
# Acts as trust anchor to be able to encrypt and send JWT to PDP and PDP can verify
# Need to convert the keys into PEM format as JWT only recogises that format and cannot directly use the key.

PIP_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PIP_public_key = PIP_private_key.public_key()

PIP_private_pem = PIP_private_key.private_bytes( #pem format of private key
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() #No encryption as JWT needs string
)

PIP_public_pem = PIP_public_key.public_bytes( #pem version of public key
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

## GPG - Key verification, attribute extraction

gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
                options=["--pinentry-mode", "loopback"])

fingerprint = "11F280405AEFFB70F72750CA6AD756CEECE2FF14"

def getAttributes(fingerprint):
    attributes = {}
    keys = gpg.list_keys(keys=[fingerprint])
    if not keys:
        print("key not found!!")
    else:
        if not keys[0]['uids']:
            print("UID not found!!")
        else:
            uid = keys[0]['uids'][-1] #UID = Name (key=Val;key=val) email
            attr = re.search(r"\((.*?)\)", uid).group(1)
            for a in attr.split(";"):
                r, s = a.split("=",1)
                attributes[r.strip()] = s.strip()
    
        return attributes

attributes = getAttributes(fingerprint)

## JWT encoding

def create_jwt(fingerprint, attributes, private_key_pem):
    payload = {
        "sub": fingerprint,
        "iss": "PGPPIP", #issuer
        "iat": int(time.time()), #issued at time
        "expiry": int(time.time() + 300) #Expiry time, set to 5 minutes from issuing
    }

    payload.update(attributes)

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    return token

jwt_attributes = create_jwt(fingerprint, attributes, PIP_private_pem)
print(jwt_attributes)

# For verifying and extracting information from JWT - ideally done on PDP side
def decode_jwt(token, public_key_pem):
    decoded_jwt = jwt.decode(token, public_key_pem, algorithms="RS256")
    return decoded_jwt

print()
print(decode_jwt(jwt_attributes, PIP_public_pem))