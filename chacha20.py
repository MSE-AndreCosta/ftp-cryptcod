#!/usr/bin/python3

import base64

m = b"You will have trouble finding the flag. The original ChaCha20 is"
c = b"0C1dXd6CI4K9Wr55upsJKGWUgtvLWaLTTp3fidbnm6vN8M299QHhhJzXGpyz+MtUFnA7zDb2HPH2DgIa8QuGgvoTB/Lmvc3QESI9jGfuO1p3lhkE3LAv5EKkAj7tbrPI2kd06CPCgg=="

N = 1 << 32

STATE_CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] 
# Computes the Chacha20 initial state with given key, position and nonce
def initialState(key, pos, nonce):
    return STATE_CONST + key + pos + nonce


# Cyclic shift left
def roll(x, n):
    return (x << n) % (2 << 31) + (x >> (32 - n))



# Double round on a Chacha20 state seen as a 16 32-bit integer array
def double_round(state):
    state[0], state[4], state[8], state[12] = quarter_round(
        state[0], state[4], state[8], state[12]
    )
    state[1], state[5], state[9], state[13] = quarter_round(
        state[1], state[5], state[9], state[13]
    )
    state[2], state[6], state[10], state[14] = quarter_round(
        state[2], state[6], state[10], state[14]
    )
    state[3], state[7], state[11], state[15] = quarter_round(
        state[3], state[7], state[11], state[15]
    )
    state[0], state[5], state[10], state[15] = quarter_round(
        state[0], state[5], state[10], state[15]
    )
    state[1], state[6], state[11], state[12] = quarter_round(
        state[1], state[6], state[11], state[12]
    )
    state[2], state[7], state[8], state[13] = quarter_round(
        state[2], state[7], state[8], state[13]
    )
    state[3], state[4], state[9], state[14] = quarter_round(
        state[3], state[4], state[9], state[14]
    )

def rev_roll(x, n):
    return roll(x, 32 - n)


def quarter_round(a, b, c, d):
    a = (a + b) % (1 << 32)
    d = roll(d ^ a, 16)
    c = (c + d) % (1 << 32)
    b = roll(b ^ c, 12)
    a = (a + b) % (1 << 32)
    d = roll(d ^ a, 8)
    c = (c + d) % (1 << 32)
    b = roll(b ^ c, 7)
    return a, b, c, d


def rev_quarter_round(a, b, c, d):
    b = rev_roll(b, 7) ^ c
    c = (c - d) % N
    d = rev_roll(d, 8) ^ a
    a = (a - b) % N
    b = rev_roll(b, 12) ^ c
    c = (c - d) % N
    d = rev_roll(d, 16) ^ a
    a = (a - b) % N
    return a, b, c, d



def rev_double_round(state):

    state[3], state[4], state[9], state[14] = rev_quarter_round(
        state[3], state[4], state[9], state[14]
    )

    state[2], state[7], state[8], state[13] = rev_quarter_round(
        state[2], state[7], state[8], state[13]
    )

    state[1], state[6], state[11], state[12] = rev_quarter_round(
        state[1], state[6], state[11], state[12]
    )

    state[0], state[5], state[10], state[15] = rev_quarter_round(
        state[0], state[5], state[10], state[15]
    )

    state[3], state[7], state[11], state[15] = rev_quarter_round(
        state[3], state[7], state[11], state[15]
    )

    state[2], state[6], state[10], state[14] = rev_quarter_round(
        state[2], state[6], state[10], state[14]
    )

    state[1], state[5], state[9], state[13] = rev_quarter_round(
        state[1], state[5], state[9], state[13]
    )

    state[0], state[4], state[8], state[12] = rev_quarter_round(
        state[0], state[4], state[8], state[12]
    )





def chacha(state):
    for _ in range(10):
        double_round(state)
    return state

def rev_chacha(state):
    for _ in range(10):
        rev_double_round(state)
    return state

# Converts a 32-bit word into 4 bytes
def w2b(word):
    return [
        (word & 0x000000FF),
        ((word & 0x0000FF00) >> 8),
        ((word & 0x00FF0000) >> 16),
        ((word & 0xFF000000) >> 24),
    ]


# Converts four bytes into a 32-bit word
def _b2w(bytes):
    return (
        bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24)
    ) & 0xFFFFFFFF


# Converts a 64 byte array into a Chacha state
def streamToState(stream):
    res = []
    for i in range(16):
        res.append(_b2w(stream[i * 4 : (i + 1) * 4]))
    return res


# Converts a chacha state into a bitstring for final xoring operation
def from_little_endian(state):
    res = []
    for i in state:
        res = res + w2b(i)
    return res


# Final xoring operation: plaitext XOR bit stream
def finalXor(pt_array, state):
    stream = from_little_endian(state)
    ciphertext = []
    for i in range(64):
        ciphertext.append(stream[i] ^ pt_array[i])
    return bytes(ciphertext)


def chacha_encrypt(plaintext, key, pos, nonce):
    if len(plaintext) != 64:
        print("plaintext needs to be 512 bits not " + str(len(plaintext)))
        return
    pt_array = bytearray(plaintext, "utf8")
    return finalXor(pt_array, chacha(initialState(key, pos, nonce)))

b64_decoded_c = base64.b64decode(c)

print("B64 decoded is ", b64_decoded_c)

m0 = m[:64]
c0 = b64_decoded_c[:64]
ks0 = []

for i in range(64):
    ks0.append(m0[i] ^ c0[i])

fs0 = streamToState(ks0)
is0 = rev_chacha(fs0)

if is0[0: len(STATE_CONST)] == STATE_CONST:
    print("Found initial state!")
else:
    print(f"Initial state wrong.Expected:\n {STATE_CONST}.\nGot:\n {is0[0:len(STATE_CONST)]}")
    exit(1)

for i in is0:
    print(f"{i:x}")

key = is0[4:12]
nonce = is0[14:]
pos = [0, 1]

print(b64_decoded_c)

is1 = initialState(key, pos, nonce)
for i in is1:
    print(f"{i:x}")

fs1 = from_little_endian(chacha(is1))

c1 = b64_decoded_c[64:128]
fs1 = fs1[:len(c1)]

m1 = []
for i in range(len(c1)):
    m1.append(c1[i] ^ fs1[i])

decoded_m = str(m0 + bytes(m1))

print(f"Message 1 is {decoded_m}")
