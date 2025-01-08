from rfc7448 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce(order):
    return randint (1, order -1)


def ECDSA_generate_keys(curve):
    private_key = randint(1, curve.order -1)
    public_key = curve.G * private_key
    return private_key, public_key


def ECDSA_sign(self, z, k):
    assert 0 < k < self._curve.order

    order = self._curve.order
    blind = Integer.random_range (min_inclusive=1, max_exclusive=order)

    blind_d = self._d * blind
    inv_blink_k = (blind * k).inverse(order)

    r = (self._curve.G * k).x % order
    s = inv_blind_k * (blind * z + blind_d * r) % order

    return (r,s)    


def ECDSA_verify(self, z, rs):
    order = self._curve.order
    sinv = rs [1].inverse(order)
    point1 = self._curve.G * ((sinv * z) % order)
    point2 = self.pointQ * ((sinv * rs[0]) % order)
    return (point1 + point2).x == rs [0]
    
