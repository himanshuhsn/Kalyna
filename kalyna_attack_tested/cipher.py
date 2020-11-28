import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

import numpy as np
from kalyna.key_expansion import KeyExpand
from tools import string2bytes, bytes2string


class KALYNA_TYPE:
    KALYNA_128_128 = {
        "Nk": 2, #number of columns in key
        "Nb": 2, #number of columns in state
        "Nr": 1 #number of rounds
    }

    KALYNA_128_256 = {
        "Nk": 4,
        "Nb": 2,
        "Nr": 14
    }

    KALYNA_256_256 = {
        "Nk": 4,
        "Nb": 4,
        "Nr": 14
    }

    KALYNA_256_512 = {
        "Nk": 8,
        "Nb": 4,
        "Nr": 18
    }

    KALYNA_512_512 = {
        "Nk": 8,
        "Nb": 8,
        "Nr": 18
    }


class Kalyna:

    def __init__(self, key, kalyna_type=KALYNA_TYPE.KALYNA_128_128):

        self._key = key

        self._nk = kalyna_type["Nk"]
        self._nb = kalyna_type["Nb"]
        self._nr = kalyna_type["Nr"]

        self._words = KeyExpand(self._nb, self._nk, self._nr).expansion(key)

    @staticmethod
    def _add_round_key(state, key):
        for word, key_word in zip(state, key):
            for j in range(4):
                word[j] ^= key_word[j]

    def encrypt(self, plaintext):
        state = plaintext.copy()

        KeyExpand.add_round_key_expand(state, self._words[0])
        for word in self._words[1:-1]:
            state = KeyExpand.encipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.encipher_round(state, self._nb)
        KeyExpand.add_round_key_expand(state, self._words[-1])

        return state

    def decrypt(self, ciphertext):
        state = ciphertext.copy()

        KeyExpand.sub_round_key_expand(state, self._words[-1])
        for word in self._words[1:-1][::-1]:
            state = KeyExpand.decipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.decipher_round(state, self._nb)
        KeyExpand.sub_round_key_expand(state, self._words[0])

        return state


if __name__ == '__main__':

    start = "0000FFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    start = "".join(reversed([start[i:i+2] for i in range(0, len(start), 2)]))
    start = int(start,16)

    key_test = string2bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

    # for 128 bit operations
    xor_count = np.array([0]*16)

    for i in range(2**8):
        plaintext = format(start+i, "032x")
        plaintext = "".join(reversed([plaintext[i:i+2] for i in range(0, len(plaintext), 2)]))
        plaintext = string2bytes(plaintext)

        kalyna_128_128 = Kalyna(key_test, KALYNA_TYPE.KALYNA_128_128)

        ciphertext = kalyna_128_128.encrypt(plaintext)
        out_str = bytes2string(ciphertext)
        list_byte = [int(out_str[i:i+2], 16) for i in range(0, len(out_str), 2)]
        print("list_byte", list_byte)
        
        for i,elm in enumerate(xor_count):
            xor_count[i] = elm^list_byte[i]

    print(xor_count)