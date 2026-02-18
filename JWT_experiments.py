import jwt
import time

fingerprint = "1234"
attributes = {
    "role": "Software Dev",
    "Department": "IT"
}

def create_jwt(key, data):
    payload = {
        "sub": key,
        "expiry": time.time() + 300
    }

    payload.update(data)

    token = jwt.encode(payload, key, algorithm="RS256")
    return token

print(jwt.decode(create_jwt(fingerprint, attributes), fingerprint, algorithms="RS256"))