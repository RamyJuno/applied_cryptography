from rfc7748 import add, sub, mult, computeVcoordinate
from algebra import mod_inv
from random import randint

p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493

BaseU = 9
BaseV = computeVcoordinate(BaseU)
base_point = (BaseU, BaseV)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

# Key Generation
def ECEG_generate_keys(base_point, order):
    private_key = randint(1, order - 1)
    public_key = mult(private_key, *base_point, p)
    return private_key, public_key

# Message Encoding
def ECencode(message):
    if message == 0:
        return (1, 0)  # Point at infinity
    if message == 1:
        return base_point
    raise ValueError("Message must be 0 or 1 for EC ElGamal.")

# Encryption
def ECEG_encrypt(message, public_key, base_point, order):
    m_point = ECencode(message)
    r = randint(1, order - 1)
    rG = mult(r, *base_point, p)  # r * G
    rY = mult(r, *public_key, p)  # r * Y
    c1 = rG
    c2 = add(*m_point, *rY, p)
    return c1, c2

# Decryption
def ECEG_decrypt(ciphertext, private_key):
    c1, c2 = ciphertext
    s = mult(private_key, *c1, p)  # s = private_key * c1
    s_inv = sub(*c2, *s, p)  # m_point = c2 - s
    return s_inv

# Testing EC ElGamal Encryption
if __name__ == "__main__":
    private_key, public_key = ECEG_generate_keys(base_point, ORDER)

    messages = [1, 0, 1, 1, 0]
    ciphertexts = [ECEG_encrypt(m, public_key, base_point, ORDER) for m in messages]

    # Combine ciphertexts for homomorphic property testing
    combined_r = (1, 0)
    combined_c = (1, 0)
    for c1, c2 in ciphertexts:
        combined_r = add(*combined_r, *c1, p)
        combined_c = add(*combined_c, *c2, p)

    # Decrypt combined ciphertext
    decrypted_point = ECEG_decrypt((combined_r, combined_c), private_key)
    brute_result = bruteECLog(decrypted_point[0], decrypted_point[1], p)

    print("Decrypted result (sum):", brute_result)
