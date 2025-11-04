# Visualizing a state
"""
word size = 64 bits unsigned integer
Si = word i within the state
State = S0 || S1 || S2 || S3 || S4
State size = 64 x 5 = 320 bits

State visualization:
S0    [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- LSB
S1    [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- LSB
S2    [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- LSB
S3    [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- LSB
S4    [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- LSB

Sizes of each param:

- Key K: 128 bits
- Nonce N: 128 bits
- Initialization Vector IV: 64 bits (fixed value for Ascon-AEAD128 = 0x00001000808c0001)

- State: 320 bits (5 words of 64 bits each)

- Rate r: 128 bits for Ascon-AEAD128
- Capacity c: 192 bits for Ascon-AEAD128

- Associated Data A: variable length
- Plaintext P: variable length
- Ciphertext C: variable length

"""


def ascon_initialize(K, N):
    """
    Initialize the Ascon state with key K, nonce N, and initialization vector IV.
    Args:
        K : The 128 bit secret key.
        N : The 128 bit nonce.
        IV: The initialization vector as a 64-bit unsigned integer.
    Returns:
        State: The initialized state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
    """
    State = [0] * 5
    # NIST SP 800-232 Ascon-AEAD128 IV
    IV = 0x00001000808C0001

    # S ← IV || K || N
    State[0] = IV
    State[1] = (K >> 64) & 0xFFFFFFFFFFFFFFFF  # Upper 64 bits of K
    State[2] = K & 0xFFFFFFFFFFFFFFFF  # Lower 64 bits of K
    State[3] = (N >> 64) & 0xFFFFFFFFFFFFFFFF  # Upper 64 bits of N
    State[4] = N & 0xFFFFFFFFFFFFFFFF  # Lower 64 bits of N

    # Perform 12 rounds of the Ascon permutation
    State = ascon_permutation(State, 12)

    # S ← S ⊕ (0^192 ‖ K)
    # XOR K into the last 2 rows of the state
    # This mixes in the key one more time
    State[3] ^= (K >> 64) & 0xFFFFFFFFFFFFFFFF  # XOR upper 64 bits of K
    State[4] ^= K & 0xFFFFFFFFFFFFFFFF  # XOR lower 64 bits of K

    return State

def ascon_permutation(State, rounds):
    """
    Apply the Ascon permutation to the state for a given number of rounds.
    Args:
        State : The current state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
        rounds: The number of rounds to apply the permutation. Must be a positive integer.
    Returns:
        State: The permuted state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
    """
    for i in range(0, rounds):
        # Constant Addition Layer (𝑝𝐶) where round constant is XORed to S2
        State[2] ^= get_round_constant(rounds, i)

        # S-box Layer (𝑝𝑆) — apply vertically for each bit position 0 to 63
        for k in range(64):  # for each column
            S_box_input = []

            for j in range(5):  # shift each row down by k and take LSB
                S_box_input.append((State[j] >> k) & 1)

            S_box_output = s_box_compute(S_box_input)

            for j in range(5):
                # clear k-th bit then set according to S_box_output[j]
                State[j] = (State[j] & ~(1 << k)) | ((S_box_output[j] & 1) << k)

        # Linear Diffusion Layer
        State = linear_diffusion_layer(State)

    return State


def process_associated_data(State, A, r=128):
    if len(A) == 0:
        # Domain separation S ← S ⊕ (0319 ‖ 1)
        State[4] ^= 1  # XOR the LSB of S4
        return State

    A_blocks = parse_input(A, 128)  # Split into blocks (returns bitstrings)
    # Pad the last block
    A_blocks[-1] = pad(A_blocks[-1], 128)

    # Then process each block (128 bit wide) by XORing with state and permuting
    for block in A_blocks:
        # Convert bitstring to integer
        block_int = int(block, 2)

        # XOR with the first two rows of State and apply permutation...
        State[0] ^= (block_int >> 64) & 0xFFFFFFFFFFFFFFFF  # XOR upper 64 bits of block
        State[1] ^= block_int & 0xFFFFFFFFFFFFFFFF  # XOR lower 64 bits of block

        State = ascon_permutation(State, 8)  # Apply 8 rounds of permutation

    # Domain separation S ← S ⊕ (0319 ‖ 1)
    State[4] ^= 1  # XOR the LSB of S4

    return State


def process_plaintext(State, P, r=128):
    C = []  # List to hold ciphertext blocks

    P_blocks = parse_input(P, 128)  # Split into blocks (returns bitstrings)
    # Keep track of the length of the last block
    l = len(P_blocks[-1])

    # Process full blocks only for now
    for block in P_blocks[:-1]:
        # Convert bitstring to integer
        block_int = int(block, 2)

        # XOR with the first two rows of State and apply permutation... S[0∶127] ← S[0∶127] ⊕ 𝑃𝑖
        State[0] ^= (block_int >> 64) & 0xFFFFFFFFFFFFFFFF  # XOR upper 64 bits of block
        State[1] ^= block_int & 0xFFFFFFFFFFFFFFFF  # XOR lower 64 bits of block

        # Extract ciphertext from state
        ct_int = (State[0] << 64) | State[1]
        C.append(ct_int.to_bytes(16, "big"))

        State = ascon_permutation(State, 8)  # Apply 8 rounds of permutation

    # Process the last block (which may be partial)
    # S[0∶127] ← S[0∶127] ⊕ pad(𝑃𝑛, 128)
    last_bits = P_blocks[-1]
    last_block_padded = pad(last_bits, 128)
    last_block_int = int(last_block_padded, 2)
    State[0] ^= (
        last_block_int >> 64
    ) & 0xFFFFFFFFFFFFFFFF  # XOR upper 64 bits of padded last block
    State[1] ^= (
        last_block_int & 0xFFFFFFFFFFFFFFFF
    )  # XOR lower 64 bits of padded last block

    # Emit ciphertext for the last block truncated to |P_n| bits
    if l > 0:
        ct_int = (State[0] << 64) | State[1]
        ct_bytes_full = ct_int.to_bytes(16, "big")
        # KAT vectors are byte-aligned; truncate to the exact plaintext byte length
        last_len_bytes = l // 8
        C.append(ct_bytes_full[:last_len_bytes])

    return State, C


def finalize(State, K):
    # S ← S ⊕ (0^128 ‖ K || 0^64)
    # XOR K into the 3rd and 4th rows of the state
    State[2] ^= (K >> 64) & 0xFFFFFFFFFFFFFFFF  # XOR upper 64 bits of K
    State[3] ^= K & 0xFFFFFFFFFFFFFFFF  # XOR lower 64 bits of K

    State = ascon_permutation(State, 12)  # Apply 12 rounds of permutation

    # S ← S ⊕ (0^192 ‖ K)
    # XOR K into the last 2 rows of the state again
    T0 = State[3] ^ ((K >> 64) & 0xFFFFFFFFFFFFFFFF)
    T1 = State[4] ^ (K & 0xFFFFFFFFFFFFFFFF)

    # Extract tag T from the last 2 rows: S3 || S4
    T_int = (T0 << 64) | T1
    T = T_int.to_bytes(16, "big")  # Convert to bytes

    return T


def ascon_aead128_enc(K, N, A, P):
    # Convert bytes to bitstrings
    A_bits = bytes_to_bits(A) if isinstance(A, bytes) else A
    P_bits = bytes_to_bits(P) if isinstance(P, bytes) else P

    # Initialize
    State = ascon_initialize(K, N)

    # Process associated data
    State = process_associated_data(State, A_bits)

    # Process plaintext
    State, C = process_plaintext(State, P_bits)

    # Finalization
    T = finalize(State, K)

    return C, T


def pad(X, r=128):
    """
    Pad the input bitstring X according to the padding rule:
    Append a single '1' bit followed by the minimum number of '0' bits
    such that the length of the padded bitstring is a multiple of r.

    Args:
        X : The input bitstring.
        r : rate - The number of input bits processed per invocation of the
            underlying permutation. Must be a positive integer.
            Note that the rate and capacity of Ascon-AEAD128 are 128 and 192 bits, respectively.
    Returns:
        str: The padded bitstring.
    """
    pad_len = r - (len(X) % r)
    return X + "1" + ("0" * (pad_len - 1))


def parse_input(X, r=128):
    """
    Parse the input bitstring X into a sequence of blocks of size r.
    Args:
        X : The input bitstring.
        r : rate - The number of input bits processed per invocation of the
            underlying permutation. Must be a positive integer.
            Note that the rate and capacity of Ascon-AEAD128 are 128 and 192 bits, respectively.
    Returns:
        list: A list of byte strings, each of size r bits.
    """
    l = len(X) // r  # floor division, so we dont go out of index range
    output_blocks = []
    for i in range(l):
        output_blocks.append(
            X[i * r : (i + 1) * r]
        )  # it's actually i(r) to (i+1)r -1, but python excludes the last index

    output_blocks.append(X[l * r :])  # append the remaining bits as the last block
    return output_blocks


# Helper functions
def bytes_to_bits(b):
    # Useful if X is given as bytes instead of bitstring
    return "".join(f"{byte:08b}" for byte in b)


def parse_bytes(X, r):
    # Useful if X is given as bytes instead of bitstring
    bitstring = bytes_to_bits(X)
    return parse_input(bitstring, r)


def get_round_constant(rnd, i):
    return CONST[16 - rnd + i]


def s_box_compute(X):
    # Where X = 𝑥0, ..., 𝑥4. A 5 bit word taken by slicing the state vertically
    # 𝑠(0,𝑗), 𝑠(1,𝑗), … , 𝑠(4,𝑗)
    result = [0] * 5
    result[0] = X[4] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] & X[0] ^ X[1] ^ X[0]
    result[1] = (
        X[4] ^ X[3] & X[2] ^ X[3] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] ^ X[0]
    )
    result[2] = X[4] & X[3] ^ X[4] ^ X[2] ^ X[1] ^ 1
    result[3] = X[4] & X[0] ^ X[4] ^ X[3] & X[0] ^ X[3] ^ X[2] ^ X[1] ^ X[0]
    result[4] = X[4] & X[1] ^ X[4] ^ X[3] ^ X[1] & X[0] ^ X[1]

    return [(b & 1) for b in result]  # ensure each output bit is either 0 or 1


def linear_diffusion_layer(S):
    x0, x1, x2, x3, x4 = S

    # applied a mask to ensure 64 bit words
    x0 = (x0 ^ rotr(x0, 19) ^ rotr(x0, 28)) & MASK64
    x1 = (x1 ^ rotr(x1, 61) ^ rotr(x1, 39)) & MASK64
    x2 = (x2 ^ rotr(x2, 1) ^ rotr(x2, 6)) & MASK64
    x3 = (x3 ^ rotr(x3, 10) ^ rotr(x3, 17)) & MASK64
    x4 = (x4 ^ rotr(x4, 7) ^ rotr(x4, 41)) & MASK64

    return [x0, x1, x2, x3, x4]


# Count the number of set bits in an integer
# https://stackoverflow.com/a/64848298/23139916
def count_set_bits(n):
    count = n.bit_count()
    return count


# Count total number of bits
# https://python-reference.readthedocs.io/en/latest/docs/ints/bit_length.html
def count_total_bits(n):
    if n == 0:
        return 1
    total_bits = n.bit_length()
    return total_bits


def int128_to_bytes(i):
    return i.to_bytes(16, "big")


def rotr(val, r):
    r %= 64
    return ((val >> r) | ((val << (64 - r)) & MASK64)) & MASK64


# Constants

# 1. Constant-Addition Layer 𝑝𝐶
CONST = [
    0x000000000000003C,
    0x000000000000002D,
    0x000000000000001E,
    0x000000000000000F,
    0x00000000000000F0,
    0x00000000000000E1,
    0x00000000000000D2,
    0x00000000000000C3,
    0x00000000000000B4,
    0x00000000000000A5,
    0x0000000000000096,
    0x0000000000000087,
    0x0000000000000078,
    0x0000000000000069,
    0x000000000000005A,
    0x000000000000004B,
]

# 2. Mask for 64 bits
MASK64 = (1 << 64) - 1
