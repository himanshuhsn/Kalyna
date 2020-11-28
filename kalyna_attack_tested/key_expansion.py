import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

import numpy as np

from kalyna import S_BOXES_ENC, S_BOXES_DEC, MDS_MATRIX, MDS_INV_MATRIX
from tools import string2bytes, bytes2string, to_type


def print_key_v2(key, l):
    ls = ["{0:0{1}x}".format(k_i, l) for k_i in key]
    return "".join(["".join([s[l - 2 * i: l - 2 * (i - 1)] for i in range(l // 2)]) for s in ls])


print_key = lambda key, l: "".join(["{0:0{1}x}".format(k_i, l) for k_i in key])


class KeyExpand:
    int2bytes = lambda num: num

    def __init__(self, nb, nk, nr):
        self._nb = nb
        self._nk = nk
        if nr%2==0:
            self._nr = nr
            self._flag = False
        else:
            self._nr = nr+1
            self._flag = True

    @staticmethod
    def multGF2(x, y):
        r = 0
        for i in range(8):
            if (y & 0x1) == 1:
                r ^= x
            hbit = x & 0x80
            x <<= 1
            if hbit == 0x80:
                x ^= 0x011d
            y >>= 1
        return r

    @staticmethod
    def add_round_key_expand(state, value):
        for i, v in enumerate(value):
            state[i] += v
        return state

    @staticmethod
    def sub_round_key_expand(state, value):
        for i, v in enumerate(value):
            state[i] -= v
        return state

    @staticmethod
    def xor_round_key_expand(state, value):
        for i, v in enumerate(value):
            state[i] ^= v

        return state

    @staticmethod
    def sub_bytes(state):
        for i, s in enumerate(state):
            state[i] = S_BOXES_ENC[i % 4][s]

        return state

    @staticmethod
    def inv_sub_bytes(state):
        for i, s in enumerate(state):
            state[i] = S_BOXES_DEC[i % 4][s]

        return state

    @staticmethod
    def shift_left(arr):
        for i in range(len(arr)):
            arr[i] <<= np.uint64(1)

    @staticmethod
    def rotate(arr):
        return np.roll(arr, -1)

    @staticmethod
    def rotate_left(arr, state_size):
        rotate_bytes = 2 * state_size + 3
        bytes_num = state_size * 8

        bytes = to_type(arr, np.uint8)
        buffer = np.array([0] * rotate_bytes, dtype=np.uint8)

        buffer[0:rotate_bytes] = bytes[0:rotate_bytes]
        bytes[0:bytes_num - rotate_bytes] = bytes[rotate_bytes:bytes_num]
        bytes[bytes_num - rotate_bytes:] = buffer[0: rotate_bytes]

        return to_type(bytes, np.uint64)

    @staticmethod
    def shift_rows(state, nb):
        nstate = np.array([0] * (len(state)), dtype=np.uint8)
        shift = -1
        for row in range(8):
            if row % (8 // nb) == 0:
                shift += 1
            for col in range(nb):
                nstate[row + ((col + shift) % nb) * 8] = state[row + col * 8]

        return nstate

    @staticmethod
    def inv_shift_rows(state, nb):
        nstate = np.array([0] * (len(state)), dtype=np.uint8)
        shift = -1
        for row in range(8):
            if row % (8 // nb) == 0:
                shift += 1
            for col in range(nb):
                nstate[row + col * 8] = state[row + ((col + shift) % nb) * 8]

        return nstate

    @staticmethod
    def matrix_multiply(state, matrix, nb):
        nstate = []
        for col in range(nb):
            word = state[col * 8: (col + 1) * 8]
            for i in range(7, -1, -1):
                product = np.uint8(0)
                for j in range(7, -1, -1):
                    product ^= KeyExpand.multGF2(word[j], matrix[i][j])
                nstate.insert(col * 8, product)
        return nstate

    @staticmethod
    def mix_columns(state, nb):
        return KeyExpand.matrix_multiply(state, MDS_MATRIX, nb)

    @staticmethod
    def inv_mix_columns(state, nb):
        return KeyExpand.matrix_multiply(state, MDS_INV_MATRIX, nb)

    @staticmethod
    def encipher_round(state, nb):
        state = to_type(state, np.uint8)
        state = KeyExpand.sub_bytes(state)
        state = KeyExpand.shift_rows(state, nb)
        state = KeyExpand.mix_columns(state, nb)
        return to_type(state, np.uint64)

    @staticmethod
    def decipher_round(state, nb):
        state = to_type(state, np.uint8)

        state = KeyExpand.inv_mix_columns(state, nb)
        state = KeyExpand.inv_shift_rows(state, nb)
        state = KeyExpand.inv_sub_bytes(state)

        return to_type(state, np.uint64)

    def key_expand_kt(self, key):

        state = np.array([0] * self._nb, dtype=np.uint64)
        state[0] += self._nb + self._nk + 1

        if self._nb == self._nk:
            state = self.add_round_key_expand(state, key)
            state = self.encipher_round(state, self._nb)
            state = self.xor_round_key_expand(state, key)
            state = self.encipher_round(state, self._nb)
            state = self.add_round_key_expand(state, key)
        else:
            state = self.add_round_key_expand(state, key[:self._nb])
            state = self.encipher_round(state, self._nb)
            state = self.xor_round_key_expand(state, key[self._nb:])
            state = self.encipher_round(state, self._nb)
            state = self.add_round_key_expand(state, key[:self._nb])

        state = self.encipher_round(state, self._nb)

        return state

    def key_expand_even(self, key, state):
        round_keys = [None] * (self._nr + 1)

        initial_data = np.ndarray(shape=(self._nk,), dtype=np.uint64)
        kt_round = np.ndarray(shape=(self._nb,), dtype=np.uint64)
        tmv = np.array([0x0001000100010001] * self._nb, dtype=np.uint64)
        local_state = np.ndarray(shape=(self._nb,), dtype=np.uint64)

        initial_data.setfield(key, key.dtype)
        round = 0

        while True:
            local_state.setfield(state, state.dtype)
            local_state = self.add_round_key_expand(local_state, tmv)

            kt_round.setfield(local_state, state.dtype)
            local_state.setfield(initial_data[:self._nb], initial_data.dtype)

            self.add_round_key_expand(local_state, kt_round)
            out_state = self.encipher_round(local_state, self._nb)
            local_state.setfield(out_state, out_state.dtype)

            self.xor_round_key_expand(local_state, kt_round)
            out_state = self.encipher_round(local_state, self._nb)
            local_state.setfield(out_state, out_state.dtype)

            self.add_round_key_expand(local_state, kt_round)

            round_keys[round] = local_state.copy()

            if self._nr == round:
                break
            if self._nk != self._nb:
                round += 2

                self.shift_left(tmv)
                local_state.setfield(state, state.dtype)
                local_state = self.add_round_key_expand(local_state, tmv)

                kt_round.setfield(local_state, state.dtype)
                local_state.setfield(initial_data[self._nb:], initial_data.dtype)

                self.add_round_key_expand(local_state, kt_round)
                out_state = self.encipher_round(local_state, self._nb)
                local_state.setfield(out_state, out_state.dtype)

                self.xor_round_key_expand(local_state, kt_round)
                out_state = self.encipher_round(local_state, self._nb)
                local_state.setfield(out_state, out_state.dtype)

                self.add_round_key_expand(local_state, kt_round)

                round_keys[round] = local_state.copy()

                if self._nr == round:
                    break
            round += 2
            self.shift_left(tmv)
            initial_data = self.rotate(initial_data)

        return state, round_keys

    def key_expand_odd(self, round_keys):
        for i in range(1, self._nr, 2):
            round_keys[i] = round_keys[i - 1].copy()
            round_keys[i] = self.rotate_left(round_keys[i], self._nb)

    def expansion(self, key):
        state = self.key_expand_kt(key)
        state, round_keys = self.key_expand_even(key, state)
        self.key_expand_odd(round_keys)
        if self._flag:
            return round_keys[:-1]
        return round_keys


if __name__ == '__main__':
    #  Round key generation: 128-bit key expansion for 128-bit block
    key = KeyExpand(2, 2, 1)
    key_test = string2bytes("000102030405060708090A0B0C0D0E0F")
    round_keys = key.expansion(key_test)

    for i, r in enumerate(round_keys):
        print(i, bytes2string(r))
    print("\n****\n")