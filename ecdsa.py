from rfc7748 import add, mult, computeVcoordinate
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

# Curve Parameters
p = 2**255 - 19  # Prime modulus of Curve25519
ORDER = 2**252 + 27742317777372353535851937790883648493  # Order of the base point
BaseU = 9
BaseV = computeVcoordinate(BaseU)  # Compute V coordinate for the base point
base_point = (BaseU, BaseV)  # Base point on the curve


# Hashing function
def H(message):
    h = SHA256.new(message.encode())
    return int(h.hexdigest(), 16)


# Generate a random nonce
def ECDSA_generate_nonce(order):
    return randint(1, order - 1)


# Key Generation
def ECDSA_generate_keys(base_point, order):
    private_key = randint(1, order - 1)
    public_key = mult(private_key, *base_point, p)  # Scalar multiplication
    return private_key, public_key


# Signing
def ECDSA_sign(private_key, message, k, base_point, order):
    message_hash = H(message)
    r_point = mult(k, *base_point, p)  # r_point = k * G
    r = r_point[0] % order
    if r == 0:
        raise ValueError("Failed to generate valid r")

    k_inv = mod_inv(k, order)  # Modular inverse of nonce
    s = (k_inv * (message_hash + private_key * r)) % order
    if s == 0:
        raise ValueError("Failed to generate valid s")

    return (r, s)


# Verifying
def ECDSA_verify(public_key, message, signature, base_point, order):
    r, s = signature
    if not (0 < r < order and 0 < s < order):
        return False

    message_hash = H(message)
    s_inv = mod_inv(s, order)
    u1 = (message_hash * s_inv) % order
    u2 = (r * s_inv) % order

    # Explicitly pass `p` to `mult` and `add`
    p1 = mult(u1, *base_point, p)  # u1 * G
    p2 = mult(u2, *public_key, p)  # u2 * Q
    result_point = add(*p1, *p2, p)  # result_point = p1 + p2

    return result_point[0] % order == r


# Test Case Integration
if __name__ == "__main__":
    # Predefined test values
    m = "A very very important message !"
    k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8

    # Expected signature values
    expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

    # Base point and order
    base_point = (BaseU, BaseV)
    order = ORDER

    # Generate the signature
    signature = ECDSA_sign(x, m, k, base_point, order)
    print("Generated Signature:", signature)

    # Validate r and s
    r, s = signature
    print("r matches expected:", r == expected_r)
    print("s matches expected:", s == expected_s)

    # Verify the signature
    public_key = mult(x, *base_point, p)  # Derive public key from private key
    is_valid = ECDSA_verify(public_key, m, signature, base_point, order)
    print("Signature valid:", is_valid)
