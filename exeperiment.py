import gnupg

gpg = gnupg.GPG(gnupghome="/Users/virwadwani/gnupgHome/gnupg_test",
                options=["--pinentry-mode", "loopback"])

input_data = gpg.gen_key_input(
    name_real = 'SOA',
    name_email = "test@example.com",
    key_type="RSA", 
    key_length=2048,
    passphrase = "123456",
    name_comment= "roles=ceo;permissions=all",
    vir = "hani"
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

'''for key in keys:
    for uid in key['uids']:
        print(uid)
    print(key['type'])'''

'''for key in keys:
    gpg.delete_keys(key['fingerprint'], secret=True, passphrase = "123456")
    gpg.delete_keys(key['fingerprint'])'''

# Generating Extra Names without generating a new key:
# Fingerprint of the key you want to modify
key_fingerprint = 'YOUR_KEY_FINGERPRINT_HERE'

# Define the new user ID
new_user_id = 'New Name <new.email@example.com>'

# Commands to send to GPG
# 'adduid' initiates the process, followed by the new ID, 'save', and 'quit'
cmd = f'adduid\n{new_user_id}\n\n1\nsave\nquit'

# Use edit_key with extra arguments to send the commands
result = gpg.submit_keys(key_fingerprint, cmd)

print(result.status)