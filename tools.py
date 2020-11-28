from itertools import chain
import numpy as np

def array2state(byte_array, nb):
    return [byte_array[nb * i: nb * (i + 1)] for i in range(len(byte_array) // nb)]


def state2array(matrix):
    return list(chain.from_iterable(matrix))


def string2bytes(string, dtype=np.uint64):
    return np.frombuffer(bytearray.fromhex(string), dtype=dtype)


def bytes2string(bytes_array):
    return "".join(["{0:0{1}x}".format(num, 2) for num in bytearray(bytes_array)])


def to_type(num_array, dtype):
    bytes_array = bytearray(num_array)
    return np.frombuffer(bytes_array, dtype=dtype)


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

to_bytes = lambda word, s: s.join(["{0:0{1}x}".format(c, 2) for c in word])


def print_state(state, s=""):
    for i, w in enumerate(state):
        print("{})".format(i), to_bytes(w, s))


if __name__ == '__main__':
    k = [283686952306183, 579005069656919567]
    words = bytes64_to_word8(k[0])
    rk = word8_to_bytes64(words)
