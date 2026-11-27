"""Crypto HW1 - Two-round Hill cipher.
Edit the PARAMETERS section with your own names, keys and initials, then run:
    python hill_cipher.py
"""
import unittest
from math import gcd

M = 26

# ===================== PARAMETERS (edit these) =====================
NAME1 = "SHAY"        # first partner (4-10 letters)
NAME2 = "GILI"      # second partner (4-10 letters)
K1_STR = "HILL"       # your K1 (not ROAD/DOOR) - must be valid
K2_STR = "FISH"       # your K2 (not ROAD/DOOR) - must be valid
# t = (initial of partner 1, initial of partner 2)
T = (ord(NAME1[0]) - 65, ord(NAME2[0]) - 65)
# ===================================================================


# ---------- helpers ----------
def to_nums(s):
    return [ord(c) - 65 for c in s]


def to_str(nums):
    return "".join(chr(n % M + 65) for n in nums)


def check_letters(s, what):
    if not isinstance(s, str) or not s or not s.isascii() or not s.isalpha():
        raise ValueError(f"{what} must contain English letters only, got {s!r}")


def key_matrix(k):
    """4-letter string -> 2x2 matrix, filled row by row."""
    check_letters(k, "Key")
    if len(k) != 4:
        raise ValueError(f"Key must have exactly 4 letters, got {k!r}")
    a, b, c, d = to_nums(k.upper())
    return [[a, b], [c, d]]


def det(K):
    return K[0][0] * K[1][1] - K[0][1] * K[1][0]


def validate(K, name="K"):
    d = det(K) % M
    if gcd(d, M) != 1:
        raise ValueError(
            f"Invalid key matrix {name}={K}: det mod 26 = {d}, "
            f"gcd(det, 26) = {gcd(d, M)} != 1, so it is not invertible mod 26")


def mod_inverse(a, m=M):
    """Own implementation (extended Euclid) - no library inverse."""
    a %= m
    r0, r1, s0, s1 = m, a, 0, 1
    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
    if r0 != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return s0 % m


def mat_inv(K):
    """K^-1 = det^-1 * adj(K)  (mod 26)."""
    validate(K)
    di = mod_inverse(det(K))
    a, b = K[0]
    c, d = K[1]
    return [[(di * d) % M, (di * -b) % M],
            [(di * -c) % M, (di * a) % M]]


def mat_mul(A, B):
    return [[sum(A[i][k] * B[k][j] for k in range(2)) % M for j in range(2)]
            for i in range(2)]


def vec_mat(x, K):
    """Row vector x times matrix K (x on the left)."""
    return [(x[0] * K[0][j] + x[1] * K[1][j]) % M for j in range(2)]


def vec_add(x, t):
    return [(x[0] + t[0]) % M, (x[1] + t[1]) % M]


def vec_sub(x, t):
    return [(x[0] - t[0]) % M, (x[1] - t[1]) % M]


def blocks(nums):
    return [nums[i:i + 2] for i in range(0, len(nums), 2)]


def pad(text):
    return text + "X" if len(text) % 2 else text


def parse_key(key):
    k1s, k2s, t = key
    K1, K2 = key_matrix(k1s), key_matrix(k2s)
    validate(K1, "K1")
    validate(K2, "K2")
    return K1, K2, [t[0] % M, t[1] % M]


# ---------- one round ----------
def round_enc(x, K, t):
    return vec_add(vec_mat(x, K), t)          # Y = XK + t


def round_dec(y, Kinv, t):
    return vec_mat(vec_sub(y, t), Kinv)       # X = (Y - t) K^-1


# ---------- Exercise 1 ----------
def NameCipher_encryption(plaintext, key, verbose=False):
    check_letters(plaintext, "Plaintext")
    K1, K2, t = parse_key(key)
    out = []
    for i, x in enumerate(blocks(to_nums(pad(plaintext.upper())))):
        y = round_enc(x, K1, t)
        z = round_enc(y, K2, t)
        if verbose and i == 0:
            print(f"  enc first block: X={x} {to_str(x)} -> Y={y} {to_str(y)}"
                  f" -> Z={z} {to_str(z)}")
        out += z
    return to_str(out)


def NameCipher_decryption(ciphertext, key, verbose=False):
    check_letters(ciphertext, "Ciphertext")
    if len(ciphertext) % 2:
        raise ValueError(f"Ciphertext length must be even, got {len(ciphertext)}")
    K1, K2, t = parse_key(key)
    K1i, K2i = mat_inv(K1), mat_inv(K2)
    out = []
    for i, z in enumerate(blocks(to_nums(ciphertext.upper()))):
        y = round_dec(z, K2i, t)   # undo round 2 FIRST
        x = round_dec(y, K1i, t)   # then undo round 1
        if verbose and i == 0:
            print(f"  dec first block: Z={z} {to_str(z)} -> Y={y} {to_str(y)}"
                  f" -> X={x} {to_str(x)}")
        out += x
    return to_str(out)


def unpad(text, original_len):
    return text[:original_len]


# ---------- Exercise 2 ----------
def recover_block(c_block, key):
    """Iterate encryption from C until we hit C again.
    The output just before returning to C is P (since E(P) = C)."""
    prev, cur, calls = c_block, NameCipher_encryption(c_block, key), 1
    while cur != c_block:
        prev, cur = cur, NameCipher_encryption(cur, key)
        calls += 1
    return prev, calls          # cycle length 1: prev == C, calls == 1


def recover_text(ciphertext, key):
    parts, counts = [], []
    for i in range(0, len(ciphertext), 2):
        p, n = recover_block(ciphertext[i:i + 2], key)
        parts.append(p)
        counts.append(n)
    return "".join(parts), counts


def max_cycle_all_blocks(key):
    best = 0
    for a in range(M):
        for b in range(M):
            best = max(best, recover_block(to_str([a, b]), key)[1])
    return best


# ---------- Exercise 3 ----------
def single_round_equivalent(key):
    K1, K2, t = parse_key(key)
    K3 = mat_mul(K1, K2)                       # matrix of the composition
    t3 = vec_add(vec_mat(t, K2), t)            # t3 = tK2 + t
    return K3, t3


# ---------- automated tests ----------
class ImplementationCheck(unittest.TestCase):
    KEY = ("ROAD", "DOOR", (3, 17))

    def test_ab(self):
        self.assertEqual(NameCipher_encryption("AB", self.KEY), "GJ")

    def test_block(self):
        self.assertEqual(NameCipher_encryption("BLOCK", self.KEY), "XHWQUP")
        self.assertEqual(NameCipher_decryption("XHWQUP", self.KEY), "BLOCKX")

    def test_intermediate(self):
        K1, _, t = parse_key(self.KEY)
        ys = [to_str(round_enc(x, K1, t)) for x in blocks(to_nums("BLOCKX"))]
        self.assertEqual(ys, ["UM", "HL", "RS"])

    def test_errors(self):
        with self.assertRaises(ValueError):
            NameCipher_encryption("AB", ("AAAA", "DOOR", (3, 17)))
        with self.assertRaises(ValueError):
            NameCipher_encryption("AB1", self.KEY)
        with self.assertRaises(ValueError):
            NameCipher_decryption("ABC", self.KEY)

    def test_repeated_encryption(self):
        self.assertEqual(recover_text("XHWQUP", self.KEY)[0], "BLOCKX")


# ---------- report output ----------
def main():
    key = (K1_STR, K2_STR, T)
    print("Key:", key)

    print("\n== Ex1.1 matrices ==")
    for nm, ks in (("K1", K1_STR), ("K2", K2_STR)):
        K = key_matrix(ks)
        d = det(K)
        print(f"{nm}={ks} {K} det={d} det mod 26={d % M} gcd={gcd(d % M, M)}")

    print("\n== Ex1.2 invalid key demo ==")
    try:
        NameCipher_encryption("TEST", ("ABCD", K2_STR, T))
    except ValueError as e:
        print("ValueError:", e)
    for bad_in in ("SH4Y",):
        try:
            NameCipher_encryption(bad_in, key)
        except ValueError as e:
            print("ValueError:", e)
    try:
        NameCipher_decryption("ABC", key)
    except ValueError as e:
        print("ValueError:", e)

    print("\n== Ex1 inverses ==")
    for nm, ks in (("K1", K1_STR), ("K2", K2_STR)):
        K = key_matrix(ks)
        Ki = mat_inv(K)
        print(f"{nm}^-1 = {Ki}   {nm}*{nm}^-1 = {mat_mul(K, Ki)}")

    print("\n== Ex1 intermediate values (first block of NAME1) ==")
    c = NameCipher_encryption(NAME1, key, verbose=True)
    NameCipher_decryption(c, key, verbose=True)

    print("\n== Ex1 table ==")
    print(f"{'Name':<12}{'Padded':<12}{'Cipher':<12}{'Recovered':<12}OK")
    for n in (NAME1, NAME2):
        c = NameCipher_encryption(n, key)
        r = NameCipher_decryption(c, key)
        print(f"{n:<12}{pad(n):<12}{c:<12}{r:<12}{r == pad(n)}"
              f"  (unpadded: {unpad(r, len(n))})")

    print("\n== Ex2 repeated encryption ==")
    for n in (NAME1, NAME2):
        c = NameCipher_encryption(n, key)
        rec, counts = recover_text(c, key)
        print(f"{n}: cipher={c} counts={counts} total={sum(counts)} "
              f"recovered={rec} matches Ex1={rec == pad(n)}")
    print("Largest count over all 676 blocks:", max_cycle_all_blocks(key))

    print("\n== Ex3 single-round equivalent ==")
    K3, t3 = single_round_equivalent(key)
    print(f"K3 = K1*K2 = {K3}, t3 = tK2 + t = {t3}")
    print(f"Same-shift K3 possible only if tK2 = 0 mod 26 (i.e. t = (0,0)); "
          f"here t={list(T)} -> {'YES' if vec_mat(list(T), key_matrix(K2_STR)) == [0, 0] else 'NO'}")
    two = NameCipher_encryption("AA", key)
    print(f"Counterexample X=AA: two rounds -> {two}, any single round E(K3,t) -> {to_str(list(T))}")
    x = to_nums(pad(NAME1))[:2]
    print(f"Verify on {to_str(x)}: single round -> {to_str(round_enc(x, K3, t3))}, "
          f"two rounds -> {NameCipher_encryption(to_str(x), key)}")


if __name__ == "__main__":
    unittest.main(argv=["x"], exit=False, verbosity=1)
    main()