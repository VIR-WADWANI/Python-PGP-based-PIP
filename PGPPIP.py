import gnupg
import re
import jwt
import time
from py_abac.provider.base import AttributeProvider

class PGPPIP(AttributeProvider):

    def __init__(self, gpg_home, public_key_path):
        print("[PGPPIP] Initializing PIP ...")
        self.gpg = gnupg.GPG(gnupghome=gpg_home, options=["--pinentry-mode", "loopback"])

        # Getting the SoA public key pem from the .pem file
        with open(public_key_path, "rb") as f:
            self.SoA_public_pem = f.read()

    #jwt_fields = ['sub', 'iss', 'iat', 'expiry', 'aud', 'nbf', 'jti']

    '''gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
                    options=["--pinentry-mode", "loopback"])'''
    
    #fingerprint = "D031FE189631DB147B774C24B5699E4D4496B14A" 

    # Verify PGP key
    def verify_pgp(self, fingerprint):
        keys = self.gpg.list_keys(keys=[fingerprint])

        if not keys[0]:
            return False
        
        if keys[0]['expires'] and int(keys[0]['expires']) < int(time.time()):
            return False
        
        #Add code for revocation check

        #Add code for signature verification

        return True

    # Extracting attributes
    def get_attribute_value(self, ace, attribute_path, ctx):
        """
        ace: subject/resource/action/context
        attribute_path: e.g. "$.role"
        ctx: evaluation context
        """

        print("This is the ctx:", ctx)
        print()
        print("attribute rquested:", attribute_path)

        fingerprint = ctx.get_attribute_value("subject", "$.fingerprint")
        print("fingerprint: ", fingerprint)

        keys = self.gpg.list_keys(keys=[fingerprint])
        if not keys:
            print("key not found!!")
            return None

        if not keys[0]['uids']:
            print("UID not found!!")
            return None
        
        #Verifying the key before extracting attributes
        if not self.verify_pgp(fingerprint):
            print("Certificate verification failure!")
            return None
        
        uid = keys[0]['uids'][-1] #UID = Name (jwt_encoded_text = key=Val;key=val) email
        attr = re.search(r"\(([^)]+)\)", uid).group(1)

        try:
            attributes = jwt.decode(attr, self.SoA_public_pem, algorithms="RS256", audience="pip")
        except Exception as e:
            print("JWT Error:", e)
            return None
        
        if attributes['expiry'] and attributes['expiry'] < int(time.time()):
            print("JWT token expired!")
            return None
        
        req_attr = attribute_path.replace("$.", "")

        print("Attributes:", attributes)
        return attributes.get(req_attr)
    
    #Testing
    def get_attribute(self, attribute_path, context=None):
        print(f"[PGPPIP] get_attribute called for {attribute_path}")
        # decode JWT or read PGP key here
        return "role"  # just test