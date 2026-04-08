import time
from cryptography import x509

#This file is for evaluating X.509 certificates to compare them to the PGP PIP created

times = []

for i in range(10):
    start = time.time()

    with open("cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    # expiry check
    cert.not_valid_after

    # extract attributes
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )

    end = time.time()
    times.append(end - start)


print(times)
avg = sum(times)/len(times)
print("avg time:", avg)