from algebra import mod_inv, int_to_bytes
from random import randint

## parameters from MODP Group 24 -- Extracted from RFC 5114

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

# Brute force logarithme
def bruteLog(g, c, p):
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

# Génération d'une paire de céls
def EG_generate_keys():
    x = randint(1, PARAM_Q - 1)
    y = pow(PARAM_G, x, PARAM_P)
    return x, y

# Chiffrement : Multiplicatif
def EGM_encrypt(message, public_key):
    # génération d'un nonce k
    k = randint(1, PARAM_Q - 1)
    c1 = pow(PARAM_G, k, PARAM_P)
    c2 = (message * pow(public_key, k, PARAM_P)) % PARAM_P
    return k, (c1, c2)

# Chiffrement : Additif
def EGA_encrypt(message, public_key):
    # génération d'un nonce k
    k = randint(1, PARAM_Q - 1)
    # Calcul des ciphertexts c1 et c2
    # c1=g^k mod et c2​ = M⋅h^k mod p
    c1 = pow(PARAM_G, k, PARAM_P)
    c2 = (pow(public_key, k, PARAM_P) * pow(PARAM_G, message, PARAM_P)) % PARAM_P
    return k, (c1, c2)

# Déchiffrement
def EG_decrypt(ciphertext, x):
    c1, c2 = ciphertext
    # s = c1^x ​mod p et  s_inv = s^-1.
    s = pow(c1, x, PARAM_P)
    s_inv = mod_inv(s, PARAM_P)
    # message = (c2 * s^-1) mod p
    message = (c2 * s_inv) % PARAM_P
    return message

# Test multiplicative homomorphic property
def test_multiplicative():
    private_key, public_key = EG_generate_keys()
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3
    r1, (c1_1, c1_2) = EGM_encrypt(m1, public_key)
    r2, (c2_1, c2_2) = EGM_encrypt(m2, public_key)
    r3 = (r1 * r2) % PARAM_Q
    c3 = ((c1_1 * c2_1) % PARAM_P, (c1_2 * c2_2) % PARAM_P)
    m3 = EG_decrypt(c3, private_key)
    print(f"Multiplicative Test:\n  m1 = {m1}\n  m2 = {m2}\n  c1 = ({c1_1}, {c1_2})\n  c2 = ({c2_1}, {c2_2})\n  Combined c3 = {c3}\n  Decrypted m3 = {m3}")
    assert m3 == (m1 * m2) % PARAM_P, f"Assertion failed: m3 = {m3}, expected {(m1 * m2) % PARAM_P}"
    print("Multiplicative test passed!")

# Test additive homomorphic property
def test_additive():
    private_key, public_key = EG_generate_keys()
    messages = [1, 0, 1, 1, 0]
    ciphertexts = [EGA_encrypt(m, public_key) for m in messages]
    r = 1
    c1 = 1
    c2 = 1
    for ct in ciphertexts:
        r = (r * ct[0]) % PARAM_Q
        c1 = (c1 * ct[1][0]) % PARAM_P
        c2 = (c2 * ct[1][1]) % PARAM_P
    combined_ciphertext = (c1, c2)
    decrypted_value = EG_decrypt(combined_ciphertext, private_key)
    m_sum = bruteLog(PARAM_G, decrypted_value, PARAM_P)
    print(f"Additive Test:\n  Messages = {messages}\n  Ciphertexts = {ciphertexts}\n  Combined Ciphertext = {combined_ciphertext}\n  Decrypted Value = {decrypted_value}\n  Sum = {m_sum}")
    print("Additive sum:", m_sum)

# Run tests
test_multiplicative()
test_additive()
