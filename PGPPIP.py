import gnupg
import re
import jwt
import time
import subprocess
from py_abac.provider.base import AttributeProvider


class PGPPIP(AttributeProvider):

    def __init__(self, gpg_home, public_key_path, trusted_signers):
        print("[PGPPIP] Initializing PIP ...")
        self.gpg = gnupg.GPG(gnupghome=gpg_home, options=["--pinentry-mode", "loopback"])
        self.trusted_signers = trusted_signers

        # Getting the SoA public key pem from the .pem file
        with open(public_key_path, "rb") as f:
            self.SoA_public_pem = f.read()

    #jwt_fields = ['sub', 'iss', 'iat', 'expiry', 'aud', 'nbf', 'jti']

    #gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
    #               options=["--pinentry-mode", "loopback"])

    def get_signers(self, fingerprint):
        #subprocess.run("export GNUPGHOME=/Users/virwadwani/gnupgHome/gnupg_test", shell=True)
        res = subprocess.run(["gpg", "--list-sigs","--with-colons", fingerprint],capture_output=True,text=True)
        print("result subprocess:",res)

        signers = []
        for r in res.stdout.splitlines():
            print()
            print(r)
            if r.startswith("sig"):
                signers.append(r.split(":")[4])

        return signers
    
    # Verify PGP key
    def verify_pgp(self, fingerprint):
        keys = self.gpg.list_keys(keys=[fingerprint])

        #Checking if key exists
        if not keys[0]:
            return False
        
        #Checking key expiry
        if keys[0]['expires'] and int(keys[0]['expires']) < int(time.time()):
            return False
        
        #Add code for revocation check

        #Verifying Key signatures
        cert_signers = self.get_signers(fingerprint)

        if not cert_signers:
            return False
        
        trust_count = 0
        for signer in cert_signers:
            print()
            print(signer)
            if signer in self.trusted_signers:
                trust_count+=1

        if trust_count >= 1:
            print("KEY VERIFIED!!")
            return True
        
        return False

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