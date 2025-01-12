from rfc7448 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def ECencode(message):
    if message == 0:
        return (1, 0)  # Point at infinity
    if message == 1:
        return base_point
    raise ValueError("Message must be 0 or 1 for EC ElGamal.")


def ECEG_generate_keys(base_point, order):
    private_key = randint(1, order - 1)
    public_key = mult(private_key, *base_point, p)
    return private_key, public_key

# Encryption
def ECEG_encrypt(message, public_key, base_point, order):
    m_point = ECencode(message)
    r = randint(1, order - 1)
    rG = mult(r, *base_point, p)  # r * G
    rY = mult(r, *public_key, p)  # r * Y
    c1 = rG
    c2 = add(*m_point, *rY, p)
    return c1, c2


def ECEG_encrypt(message, public_key, base_point, order):
    m_point = ECencode(message)
    r = randint(1, order - 1)
    rG = mult(r, *base_point, p)  # r * G
    rY = mult(r, *public_key, p)  # r * Y
    c1 = rG
    c2 = add(*m_point, *rY, p)
    return c1, c

# Testing EC ElGamal Encryption with Homomorphic Property
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = ECEG_generate_keys(base_point, ORDER)
    
    # Messages to encrypt
    messages = [1, 0, 1, 1, 0]
    
    # Encrypt messages
    ciphertexts = [ECEG_encrypt(m, public_key, base_point, ORDER) for m in messages]
    
    # Combine ciphertexts
    combined_r = (1, 0)  # Start with point at infinity
    combined_c = (1, 0)
    for c1, c2 in ciphertexts:
        combined_r = add(*combined_r, *c1, p)
        combined_c = add(*combined_c, *c2, p)
    
    # Decrypt combined ciphertext
    decrypted_point = ECEG_decrypt((combined_r, combined_c), private_key)
    decrypted_message = bruteECLog(decrypted_point[0], decrypted_point[1], p)
    
    print(f"Decrypted message sum: {decrypted_message}")
    assert decrypted_message == 3, "Decryption or summing failed"
