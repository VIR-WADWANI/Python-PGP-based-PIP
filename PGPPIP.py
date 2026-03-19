import gnupg
import re
import jwt
import time

jwt_fields = ['sub', 'iss', 'iat', 'expiry', 'aud', 'nbf', 'jti']

# Getting the SoA public key pem from the .pem file
with open("SoA_public_pem.pem", "rb") as f:
    SoA_public_pem = f.read()


## GPG - Key verification, attribute extraction

gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
                options=["--pinentry-mode", "loopback"])

fingerprint = "D031FE189631DB147B774C24B5699E4D4496B14A" 

# Verify PGP key
def verify_pgp(fingerprint):
    keys = gpg.list_keys(keys=[fingerprint])

    if not keys[0]:
        return False
    
    if keys[0]['expires'] and int(keys[0]['expires']) < int(time.time()):
        return False
    
    #Add code for revocation check

    #Add code for signature verification

    return True

# Extracting attributes
def getAttributes(fingerprint):
    keys = gpg.list_keys(keys=[fingerprint])
    if not keys:
        print("key not found!!")
    else:
        if not keys[0]['uids']:
            print("UID not found!!")
        else:
            uid = keys[0]['uids'][-1] #UID = Name (key=Val;key=val) email
            attr = re.search(r"\(([^)]+)\)", uid).group(1)
            attributes = jwt.decode(attr, SoA_public_pem, algorithms="RS256", audience="pip")
            
            if attributes['expiry'] and attributes['expiry'] > int(time.time()):
                print("JWT token expired!")
                return None
            
            for field in jwt_fields:
                attributes.pop(field, None)

        return attributes

if verify_pgp(fingerprint): #To verify key before extracting attributes
    attributes = getAttributes(fingerprint)
else:
    print("Key not verified!")

print()
print(attributes)