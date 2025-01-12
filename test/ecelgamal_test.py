from rfc7748 import add, sub, mult, computeVcoordinate
from algebra import mod_inv
from random import randint

# Paramètres de la courbe
p = 2**255 - 19  # Modulo de Curve25519

# Ordre du point de base
ORDER = 2**252 + 27742317777372353535851937790883648493 
BaseU = 9
# Compute V coordinate du point de base U
BaseV = computeVcoordinate(BaseU)

# Point de base sur le coubre
base_point = (BaseU, BaseV)

# Brute force logarithme
def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

# Génération d'une paire de clés
def ECEG_generate_keys(base_point, order):
    # 1 < x < ordre - 1 et y = x * G
    x = randint(1, order - 1)
    y = mult(x, *base_point, p)
    return x, y

# Encode le message sur la courbe elliptique
def ECencode(message):
    if message == 0:
        return (1, 0)
    if message == 1:
        return base_point
    raise ValueError("Message must be 0 or 1")

# Chiffrement du message
def ECEG_encrypt(message, public_key, base_point, order):
    m_point = ECencode(message)
    # génération du nonce k
    k = randint(1, order - 1)
    kG = mult(k, *base_point, p) 
    kY = mult(k, *public_key, p)
    # c1 = nonce * G et c2 = Message + nonce * clé_pubique
    c1 = kG
    c2 = add(*m_point, *kY, p)
    return c1, c2

# Déchiffrement du message
def ECEG_decrypt(ciphertext, x):
    c1, c2 = ciphertext
    # s = clé privée * c1
    s = mult(x, *c1, p)  
    # s_inv ou m_point = c2 - s
    s_inv = sub(*c2, *s, p) 
    return s_inv

# Test ECElgamal
if __name__ == "__main__":
    private_key, public_key = ECEG_generate_keys(base_point, ORDER)

    messages = [1, 0, 1, 1, 1]
    print("Messages : ", messages)
    ciphertexts = [ECEG_encrypt(m, public_key, base_point, ORDER) for m in messages]
    # Addition des ciphertexts : homomorphique
    combined_r = (1, 0)
    combined_c = (1, 0)
    for c1, c2 in ciphertexts:
        combined_r = add(*combined_r, *c1, p)
        combined_c = add(*combined_c, *c2, p)

    # Déchiffrement des ciphertexts
    decrypted_point = ECEG_decrypt((combined_r, combined_c), private_key)
    brute_result = bruteECLog(decrypted_point[0], decrypted_point[1], p)

    print("Somme des messages :", brute_result)
