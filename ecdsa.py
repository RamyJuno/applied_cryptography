from rfc7748 import add, mult, computeVcoordinate
from Cryptodome.Hash import SHA256
from random import randint
from algebra import mod_inv

# Paramètres de la courbe
p = 2**255 - 19  # Modulo de Curve25519
ORDER = 2**252 + 27742317777372353535851937790883648493  # Ordre du point de base
BaseU = 9
BaseV = computeVcoordinate(BaseU)  # Compute V coordinate du point de base
base_point = (BaseU, BaseV)  # Point de base sur le coubre


# Fonction de hashage
def H(message):
    h = SHA256.new(message.encode())
    return int(h.hexdigest(), 16)


# Génération du nonce k
def ECDSA_generate_nonce(order):
    return randint(1, order - 1)


# Génération d'une paire de clé
def ECDSA_generate_keys(base_point, order):
    x = randint(1, order - 1)
    # Multiplication scalaire de la clé privée et du point de base
    y = mult(x, *base_point, p)
    return x, y


# Signature du message
def ECDSA_sign(private_key, message, k, base_point, order):
    message_hash = H(message)
    # k = ECDSA_generate_nonce(ORDER)
    # Point R = nonce * G
    r_point = mult(k, *base_point, p)
    r = r_point[0] % order
    if r == 0:
        raise ValueError("Mauvais r généré")

    k_inv = mod_inv(k, order)
    s = (k_inv * (message_hash + private_key * r)) % order
    if s == 0:
        raise ValueError("Mauvais s généré")

    return (r, s)


# Vérification
def ECDSA_verify(public_key, message, signature, base_point, order):
    r, s = signature
    if not (0 < r < order and 0 < s < order):
        return False

    message_hash = H(message)
    s_inv = mod_inv(s, order)
    u1 = (message_hash * s_inv) % order
    u2 = (r * s_inv) % order

    # p1 = u1 * G et p2 = u2 * G
    p1 = mult(u1, *base_point, p)  
    p2 = mult(u2, *public_key, p)

    # result_point = p1 + p2
    result_point = add(*p1, *p2, p)

    # Si result_point[0] % order == r, alors la signature est authentifuqe
    return result_point[0] % order == r


# Test ECDSA
if __name__ == "__main__":
    # Paramètre de test
    m = "A very very important message !"
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8

    # Valeurs attendues de la signature
    expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

    # Paramètre du point de base et ordre
    base_point = (BaseU, BaseV)
    order = ORDER

    # Génération de la signature
    signature = ECDSA_sign(x, m, k, base_point, order)
    print("Generated Signature:", signature)

    # Test : Validation de r et s
    r, s = signature
    print("r matches expected:", r == expected_r)
    print("s matches expected:", s == expected_s)

    # Vérification de la signature
    public_key = mult(x, *base_point, p) 
    print("Signature validée ? ", str(ECDSA_verify(public_key, m, signature, base_point, order)))
