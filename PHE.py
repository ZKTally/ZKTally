import hashlib
import random
import secrets
from Crypto.Util import number
from math import gcd

# PHEUtil
def hash_to_int(*args, q=2**256):
    h = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            h.update(arg.to_bytes((arg.bit_length() + 7) // 8, byteorder='big'))
        else:
            h.update(arg)
    return int.from_bytes(h.digest(), byteorder='big') % q

def lcm(a, b):
    return abs(a*b) // gcd(a, b)

# Secure key generation
def keygen(bits=2048):
    """Generates secure Paillier keypair."""
    p = number.getPrime(bits // 2, randfunc=secrets.token_bytes)
    q = number.getPrime(bits // 2, randfunc=secrets.token_bytes)
    while p == q:
        q = number.getPrime(bits // 2, randfunc=secrets.token_bytes)
    n = p * q
    g = n + 1
    N2 = n * n

    lam = lcm(p-1, q-1)
    u = pow(g, lam, N2)
    L = (u - 1) // n
    mu = pow(L, -1, n)

    public_key = (n, g, N2)
    private_key = (lam, mu)

    return public_key, private_key

# ==== Encryption ====
def encrypt(m, public_key):
    n, g, N2 = public_key
    r = secrets.randbelow(n)
    while r == 0:
        r = secrets.randbelow(n)
    c = (pow(g, m, N2) * pow(r, n, N2)) % N2
    return c, r

# ==== Decryption ====
def decrypt(c, public_key, private_key):
    n, g, N2 = public_key
    lam, mu = private_key
    u = pow(c, lam, N2)
    L = (u - 1) // n
    m = (L * mu) % n
    return m

# ==== NIZK OR-Proof for m ∈ {0,1} ====
def prove_01(c, r, m, public_key):
    try:
        n, g, N2 = public_key
        inv_g = pow(g, -1, N2)
        c_i = {0: c, 1: (c * inv_g) % N2}
        s, a, e, z = {}, {}, {}, {}

        for i in (0, 1):
            if i == m:
                s[i] = secrets.randbelow(n)
                while s[i] == 0:
                    s[i] = secrets.randbelow(n)
                a[i] = pow(s[i], n, N2)
            else:
                e[i] = secrets.randbelow(2**256)
                z[i] = secrets.randbelow(n)
                while z[i] == 0:
                    z[i] = secrets.randbelow(n)
                c_inv_e = pow(pow(c_i[i], e[i], N2), -1, N2)
                a[i] = (pow(z[i], n, N2) * c_inv_e) % N2

        e_total = hash_to_int(
            c.to_bytes((c.bit_length() + 7) // 8, 'big'),
            a[0].to_bytes((a[0].bit_length() + 7) // 8, 'big'),
            a[1].to_bytes((a[1].bit_length() + 7) // 8, 'big'),
        )
        e[m] = (e_total - e[1 - m]) % (2**256)
        z[m] = (s[m] * pow(r, e[m], n)) % n

        return {'a0': a[0], 'a1': a[1], 'e0': e[0], 'e1': e[1], 'z0': z[0], 'z1': z[1]}
    except:
        print("[*] Failed to generate proof")
        return {'a0': 0, 'a1': 0, 'e0': 0, 'e1': 0, 'z0': 0, 'z1': 0}

def verify_01(c, proof, public_key):
    try:
        n, g, N2 = public_key
        inv_g = pow(g, -1, N2)
        c_i = {0: c, 1: (c * inv_g) % N2}
        a0, a1 = proof['a0'], proof['a1']
        e0, e1 = proof['e0'], proof['e1']
        z0, z1 = proof['z0'], proof['z1']

        e_total = hash_to_int(
            c.to_bytes((c.bit_length() + 7) // 8, 'big'),
            a0.to_bytes((a0.bit_length() + 7) // 8, 'big'),
            a1.to_bytes((a1.bit_length() + 7) // 8, 'big'),
        )
        if (e0 + e1) % (2**256) != e_total:
            return False

        for i, a_i, e_i, z_i in [(0, a0, e0, z0), (1, a1, e1, z1)]:
            lhs = pow(z_i, n, N2)
            rhs = (a_i * pow(c_i[i], e_i, N2)) % N2
            if lhs != rhs:
                return False
        return True
    except:
        return False

# ==== Example Usage ====
if __name__ == "__main__":
    # Key generation
    public_key, private_key = keygen(bits=2048)
    n, g, N2 = public_key

    # Voter chooses m = 0 or 1
    for m in [-3,-2,-1,0,1,2,3]:
        print("\n[*] Prove and Verify m = {}".format(m))
        c, r = encrypt(m, public_key)

        # Prove vote validity (0 or 1)
        proof = prove_01(c, r, m, public_key)
        valid = verify_01(c, proof, public_key)

        # Decrypt the vote
        m_decrypted = decrypt(c, public_key, private_key)

        print("[*] Proof valid:", valid)
        print("[*] Original message:", m)
        print("[*] Decrypted message:", m_decrypted)
