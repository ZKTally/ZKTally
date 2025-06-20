import hashlib
import random
from ecdsa import SECP256k1, SigningKey, VerifyingKey, ellipticcurve
import base58

curve = SECP256k1
G = curve.generator
order = curve.order

def hash_to_int(data: bytes) -> int:
    return int(hashlib.sha256(data).hexdigest(), 16) % order

def key_image(private_key):
    """Generate a key image from a private key"""
    pub_point = private_key.verifying_key.pubkey.point
    h_point = hash_to_point(pub_point)
    return h_point * private_key.privkey.secret_multiplier

def hash_to_point(point):
    """Map a point to another point on the curve"""
    data = point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big')
    h = hash_to_int(data)
    return h * G

def sign(message: bytes, private_index, pub_keys, priv_key):
    n = len(pub_keys)
    key_img = key_image(priv_key)
    c = [0] * n
    r = [0] * n

    # Step 1: pick random values
    u = random.randint(1, order - 1)
    P = pub_keys
    L = [None] * n
    R = [None] * n

    L[private_index] = u * G
    R[private_index] = u * hash_to_point(P[private_index].pubkey.point)

    # Step 2: compute challenges and responses
    j = (private_index + 1) % n
    c[j] = hash_to_int(message + L[private_index].x().to_bytes(32, 'big'))

    for i in range(j, private_index + n):
        idx = i % n
        r[idx] = random.randint(1, order - 1)
        L[idx] = r[idx] * G + c[idx] * P[idx].pubkey.point
        R[idx] = r[idx] * hash_to_point(P[idx].pubkey.point) + c[idx] * key_img
        c[(idx + 1) % n] = hash_to_int(message + L[idx].x().to_bytes(32, 'big'))

    # Compute r for the real signer
    r[private_index] = (u - priv_key.privkey.secret_multiplier * c[private_index]) % order

    return {"c0": c[0], "r": r, "key_image": key_img, "pub_keys": pub_keys}

def verify(message: bytes, signature):
    c = signature["c0"]
    r = signature["r"]
    P = signature["pub_keys"]
    key_img = signature["key_image"]
    n = len(P)

    for i in range(n):
        L = r[i] * G + c * P[i].pubkey.point
        R = r[i] * hash_to_point(P[i].pubkey.point) + c * key_img
        c = hash_to_int(message + L.x().to_bytes(32, 'big'))

    return c == signature["c0"]