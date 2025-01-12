from algebra import mod_inv
from Cryptodome.Hash import SHA256
from random import randrange

## parameters from MODP Group 24 -- Extracted from RFC 5114

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

# Fonction de hashage
def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

# Génération du nonce k
def DSA_generate_nonce(q):
    return randrange(1, q - 1)

# Génération des clés publiques et privées
def DSA_generate_keys(g, p, q):
    x = randrange(1, q - 1)
    y = pow(g, x, p)

# Signature du message
def DSA_sign(g, p, q, x, m):
    while True:
            # SHA_256(message)
            h = H(m)
            # Generation du nonce
            k = DSA_generate_nonce(q)
            # Calcul de r
            r = pow(g, k, p) % q
            # Cacul de s
            try:
                s = (mod_inv(k, q) * (h + x * r)) % q
                return hex(r), hex(s)
            except ZeroDivisionError:
                pass  

# Vérification de la signature
def DSA_verify(r, s, g, p, q, y, m):
    # On s'assure que 0 < r < q et que 0 < s < q 
    if not 0 < r < q or not 0 < s < q :
        return False
    w = pow(s, -1, q)
    u1 = (H(m) * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    # Si v == r alors la signature est authentique
    return v == r
