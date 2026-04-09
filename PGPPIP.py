
#Custom PIP
#Receives fingerprint from PDP, Validates the certificate, extracts attribute, and returns to PDP

import gnupg
import re
import jwt
import time
import subprocess
from py_abac.provider.base import AttributeProvider

#Creating the PGPPIP class that inherits the AttributeProvider class as required by py-abac
class PGPPIP(AttributeProvider):

    def __init__(self, gpg_home, public_key_path, trusted_signers):
        self.gpg = gnupg.GPG(gnupghome=gpg_home, options=["--pinentry-mode", "loopback"])
        self.trusted_signers = trusted_signers

        # Getting the SoA public key pem from the .pem file which is required for decoding JWT
        with open(public_key_path, "rb") as f:
            self.SoA_public_pem = f.read()

    # Returns all the signers of a certificate
    def get_signers(self, fingerprint):
        # Uses subprocess to run terminal command to get the output of all signers
        res = subprocess.run(["gpg", "--homedir", "/Users/virwadwani/gnupgHome/gnupg_test", "--list-sigs","--with-colons", fingerprint],capture_output=True,text=True)

        # Parses the output to then extract just the signer keys
        signers = []
        for r in res.stdout.splitlines():
            if r.startswith("sig"):
                signers.append(r.split(":")[4])

        return signers
    
    # Verify the PGP key
    def verify_pgp(self, fingerprint):
        keys = self.gpg.list_keys(keys=[fingerprint])

        # Checking if key exists
        if not keys:
            print("Key Not found!")
            return False
        
        if not keys[0]['uids']:
            print("UID not found!!")
            return False
        
        # Checking key expiry
        if keys[0]['expires'] and int(keys[0]['expires']) < int(time.time()):
            return False

        # Verifying the signers of the key
        cert_signers = self.get_signers(fingerprint)

        if not cert_signers:
            return False
        
        # Checking if more than 1 signer exists only then the certificate can be trusted
        trust_count = 0
        for signer in cert_signers:
            if signer in self.trusted_signers:
                trust_count+=1

        if trust_count >= 1:
            return True
        
        return False

    # Extracting attributes
    def get_attribute_value(self, ace, attribute_path, ctx):
        """
        ace: subject/resource/action/context
        attribute_path: e.g. "$.role"
        ctx: evaluation context
        """
        #start = time.time()  # For timing evaluation
        # Gets the fingerprint from the request context sent from PDP
        fingerprint = ctx.get_attribute_value("subject", "$.fingerprint")

        keys = self.gpg.list_keys(keys=[fingerprint])
        
        # Verifying the key before extracting attributes
        if not self.verify_pgp(fingerprint):
            print("Certificate verification failure!")
            return None
        
        # Using regular expression to extract just the encoded JWT from the certificate
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

        #end = time.time() # For timing Evaluation
        #print("pip time:", end - start) # For timing Evaluation

        if not attributes.get(req_attr):
            print("Attribute Not in Certificate!")
            
        return attributes.get(req_attr)
    