import random


# SHA-256 hash function (https://en.wikipedia.org/wiki/SHA-2)
def H(msg):
    def int2bits(i, n=None):
        return bin(i)[2:] if n is None else bin(i)[2:].rjust(n, '0')

    def chunks(s, n):
        chunks = []
        i = 0
        while i < len(s):
            chunks.append(s[i:i+n])
            i += n
        return chunks

    def rightrotate(s, n):
        n = n % len(s)
        return s[-n:] + s[:-n]

    def rightshift(s, n):
        if n >= len(s):
            return '0' * len(s)
        return '0' * n + s[:-n]

    def bitwise_fn(a, b, fn):
        assert len(a) == len(b)
        c = [None] * len(a)
        for i in range(len(a)):
            assert a[i] in ['0', '1'] and b[i] in ['0', '1']
            c[i] = '1' if fn(a[i], b[i]) else '0'
        return ''.join(c)

    def bitxor(a, b):
        return bitwise_fn(a, b, lambda x, y: x != y)

    def bitand(a, b):
        return bitwise_fn(a, b, lambda x, y: x + y == '11')

    def bitnot(a):
        return bitxor(a, '1' * len(a))

    def addmodn(a, b, n):
        assert len(a) >= n and len(b) >= n
        c = [None] * n
        carry = 0
        for i in reversed(range(n)):
            assert a[i] in ['0', '1'] and b[i] in ['0', '1']
            s = int(a[i]) + int(b[i]) + carry
            c[i] = str(s % 2)
            carry = s // 2
        return ''.join(c)

    def mbitxor(terms):
        assert len(terms) >= 2
        x = bitxor(terms[0], terms[1])
        for i in range(2, len(terms)):
            x = bitxor(x, terms[i])
        return x

    def maddmodn(terms, n):
        assert len(terms) >= 2
        s = addmodn(terms[0], terms[1], n)
        for i in range(2, len(terms)):
            s = addmodn(s, terms[i], n)
        return s

    # Initialize hash values:
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Initialize array of round constants:
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    h0 = int2bits(h0, 32)
    h1 = int2bits(h1, 32)
    h2 = int2bits(h2, 32)
    h3 = int2bits(h3, 32)
    h4 = int2bits(h4, 32)
    h5 = int2bits(h5, 32)
    h6 = int2bits(h6, 32)
    h7 = int2bits(h7, 32)
    for i in range(len(k)):
        k[i] = int2bits(k[i], 32)

    # Pre-processing (Padding):
    L = len(msg)
    assert L % 8 == 0
    msg = msg + '1'
    K = 512 - ((L + 1 + 64) % 512)
    assert K >= 0 and K < 512
    assert (L + 1 + K + 64) % 512 == 0
    msg = msg + '0' * K
    msg = msg + int2bits(L, 64)
    assert len(msg) % 512 == 0

    # Process the message in successive 512-bit chunks:
    for chunk in chunks(msg, 512):
        w = chunks(chunk, 32) + [None] * 48
        assert len(w) == 64
        for i in range(16, 64):
            s01 = rightrotate(w[i-15], 7)
            s02 = rightrotate(w[i-15], 18)
            s03 = rightshift(w[i-15], 3)
            s0 = mbitxor((s01, s02, s03))
            s11 = rightrotate(w[i-2], 17)
            s12 = rightrotate(w[i-2], 19)
            s13 = rightshift(w[i-2], 10)
            s1 = mbitxor((s11, s12, s13))
            w[i] = maddmodn((w[i-16], s0, w[i-7], s1), 32)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(64):
            S11 = rightrotate(e, 6)
            S12 = rightrotate(e, 11)
            S13 = rightrotate(e, 25)
            S1 = mbitxor((S11, S12, S13))
            ch = bitxor(bitand(e, f), bitand(bitnot(e), g))
            temp1 = maddmodn((h, S1, ch, k[i], w[i]), 32)
            S01 = rightrotate(a, 2)
            S02 = rightrotate(a, 13)
            S03 = rightrotate(a, 22)
            S0 = mbitxor((S01, S02, S03))
            maj = mbitxor((bitand(a, b), bitand(a, c), bitand(b, c)))
            temp2 = addmodn(S0, maj, 32)

            h = g
            g = f
            f = e
            e = addmodn(d, temp1, 32)
            d = c
            c = b
            b = a
            a = addmodn(temp1, temp2, 32)

        h0 = addmodn(h0, a, 32)
        h1 = addmodn(h1, b, 32)
        h2 = addmodn(h2, c, 32)
        h3 = addmodn(h3, d, 32)
        h4 = addmodn(h4, e, 32)
        h5 = addmodn(h5, f, 32)
        h6 = addmodn(h6, g, 32)
        h7 = addmodn(h7, h, 32)

    # Produce the final hash value (big-endian):
    return int(''.join([h0, h1, h2, h3, h4, h5, h6, h7]), 2)


# Euclidean algorithm (https://en.m.wikipedia.org/wiki/Euclidean_algorithm)
def gcd(a, b):
    while a != b:
        if a > b:
            a = a - b
        else:
            b = b - a
    return a


# multiplicative inverse using the extended Euclidean algorithm
# (https://en.m.wikipedia.org/wiki/Extended_Euclidean_algorithm)
def mult_inv(a, n):
    t, newt = 0, 1
    r, newr = n, a

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    assert r <= 1, "a is not invertible"

    return t if t >= 0 else t + n


# modular exponentiation by squaring
# (https://en.m.wikipedia.org/wiki/Modular_exponentiation)
def mod_exp(base, exponent, modulus):
    if modulus == 1:
        return 0

    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus

    return result


# deterministic primality test
def is_prime_det(n):
    d = 2
    while d ** 2 < n:
        if n % d == 0:
            return False
        d += 1
    return True


# Miller-Rabin probabilistic primality test
# (https://en.m.wikipedia.org/wiki/Primality_test)
def is_prime_prob(n, num_trials=64):
    # if is_prime_prob(n) = False, then n is definitely not prime, whereas
    # if is_prime_prob(n) = True, then n is prime with probability at least
    # 1 - 4 ** (-num_trials)
    s = 0
    while ((n - 1) // (2 ** s)) % 2 == 0:
        s += 1
    d = (n - 1) // (2 ** s)
    assert (2 ** s) * d + 1 == n

    for _ in range(num_trials):
        a = random.randrange(2, n - 1)
        if (mod_exp(a, d, n) not in [1, n - 1]
            and all([mod_exp(1, (2 ** r) * d, n) != n - 1 for r in range(s)])):
            return False
    return True


def n_bit_prime(n, is_prime=is_prime_prob):
    candidate = random.getrandbits(n)
    while not is_prime(candidate):
        candidate += 1
    return candidate


# RSA key generation, signing, and verification functions
# (https://en.m.wikipedia.org/wiki/RSA_(cryptosystem))
def G(n=512):
    # n is the desired key length; 2048 or larger used in practice
    p = n_bit_prime(n // 2 - 1)
    q = n_bit_prime(n // 2 + 3)
    n = p * q

    lcm = lambda a, b: abs(a * b) // gcd(a, b)
    lam = lcm(p-1, q-1)
    
    e = 65537
    d = mult_inv(e, lam)
    assert (e * d) % lam == 1

    return (n, e), (n, d)

def S(sk, msg):
    n, d = sk
    h = H(msg)
    assert 0 <= h < n
    sigma = mod_exp(h, d, n)
    return sigma

def V(pk, msg, sigma):
    n, e = pk
    return H(msg) == mod_exp(sigma, e, n)
