#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 9 ##################################################################

"""
List you collaborators here:
                                party one
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""
import HW9_helper
from binascii import hexlify, unhexlify
from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import HMAC, SHA256

first_sig = HW9_helper.Signature(78963682628359021178354263774457319969002651313568557216154777320971976772376, 5416854926380100427833180746305766840425542218870878667299, 5568285309948811794296918647045908208072077338037998537885)
second_sig = HW9_helper.Signature(62159883521253885305257821420764054581335542629545274203255594975380151338879, 1063435989394679868923901244364688588218477569545628548100, 5568285309948811794296918647045908208072077338037998537885)
mod_val = 6277101735386680763835789423176059013767194773182842284081




def q1_break_ecdsa(n, sig1, sig2):
    """Question 1: Breaking (EC)DSA with poor randomness

    The Digital Signature Algorithm (DSA) operates similarly to the Schnorr
    signature algorithm we discussed in class.

    Like most public key signature algorithms,
    DSA is (1) randomized and (2) incredibly fragile against reuse of the
    randomness, breaking completely and yielding the key when this occurs.

    The DRM underlying the Sony Playstation 3 was cracked due to this mistake.

    Your objective:
        Solve the problem listed at https://id0-rsa.pub/problem/17/.
        Note that `n` is the modulus used in the problem, and `z1` and `z2`
        are the *hashes* of the messages, not just the messages themselves.

        The ePrint paper linked in the problem statement may be of value to you.

    Your Task:
        Complete the function below to return the secret key used, given two
        signatures under the same nonce.

        For full credits, your solution should work with any *bad* signatures
        provided to this function.

    Args:
        n     (int)                   : the modulus used to generate the
                                        signatures
        sig1  (HW9_helper.Signature) : First signature (z, s, r)
        sig2  (HW9_helper.Signature) : Second signature (z, s, r)

    Output:
        ret         (bytes)       :  DSA key used to generate the signatures.

    How to verify your solution:
        Use the submission box at the bottom of https://id0-rsa.pub/problem/17/
        to validate the shared nonce. (Note that the nonce is *different* than
        the DSA key that I am requiring you to output, although once you have
        one then you should easily be able to compute the other.)
    """
    
    sub_hashes = sig1.z - sig2.z
    inverse = HW9_helper.mod_inv(sig1.s - sig2.s,n)
    k = (sub_hashes * inverse) % n
    x = ((sig1.s * k) - sig1.z) *HW9_helper.mod_inv(sig1.r,n) % n
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    


def q2_symmetric_ratchet(init_chain_key, msg_n):
    """Question 2: Symmetric-key ratchet System

    As discussed in lecture 16, ratching is a technique used to "evolve"
    encryption keys in a cryptographic system. One common approach to key ratching
    is by using Hash functions. More specifically, ratching is done using a Key
    Derivation Function (KDF) that uses hashing internally to evolve the secret
    keys.

    The message keys generated with ratching are then used to perform various
    symmetric cryptographical operations. For that reason, the length of the
    message key is usually the same as the block size of the Block cipher used
    (for example, it will be 16 bytes if AES is used).

    Your Task:
        Simulate a Symmetric Ratchet System using HMAC-SHA2 as your KDF function.
        Your function will take an initial chain key, along with the message
        number msg_n, and then compute the corresponding message-key (of length
        16 bytes) of the msg_n'th message in the key chain.

    Notes:
        You can assume that msg_n is >= 1, where 1 corresponds to the first
        derived key after one iteration of the KDF.

        As noted in the Signal specification, a the KDF function needs a "constant"
        value to be passed along with the key, for this question, you can use
        a constant value of 16 bytes of zeros (b'\x00' * 16).

        When handling the output of your KDF function, make sure the last half
        (16-bytes) are used as the msg_key, the rest of the bytes should be used
        as your new chain_key.

        Check the Signal specification (Section 2.2) here for more details:
            https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet

    Args:
        init_chain_key  (bytes): 16-bytes key to be used as the initial chain key.

        msg_n           (int):  The order number of the message for which the
                                key should be generated.
                                ** Please keep in mind that this value >= 1
                                            (not 0-indexed) **
    Output:
        ret             (bytes): 16-bytes bytes message key that should be used to with the message number n.

    How to verify your solution:
    ```
        assert(q2_symmetric_ratchet(bytes.fromhex("00"*16), 10) == "ef16fc0952b4e1c7905280623c50e860")
        assert(q2_symmetric_ratchet(bytes.fromhex("00"*16), 7)  == "ae8fdc968633ee9f6aae746d58f1fa2c")
        assert(q2_symmetric_ratchet(bytes.fromhex("99"*16), 1) ==  "7aa7cb289cc1f1b6d7d6efe83ba900f2")
    ```
    """
    constant = b'\x00'*16
    key = init_chain_key
    for i in range(msg_n):
        h = HMAC.new(key, digestmod=SHA256)
        h.update(constant)
        key = h.digest()[:16]
        msg_key = h.digest()[16:]
    return msg_key


def q3_public_ratchet(public_component, dh_secret, init_root_key, msg_n):
    """Question 3: Diffie-Hellman ratchet System

    Your Task:
        In this question, you will extend the ratchet system you built in q2
        to derive chain keys using the Diffie-Hellman shared secret. For this
        problem, you should follow the technical details illustrated in Lecture
        16, slide 31.

        For simplicity, you only need to derive a single "Receiving" chain key
        since you have a single public key component. This setup will simulate
        the Signal protocol when one of the parties is offline, and messages
        are being encrypted with keys derived under a single "ratchet". In the
        other scenario where both parties are online, the public key "ratchet"
        is updated everytime any party sends a message back, therefore, the
        chain key will updated, allowing the disposal of the old chain key
        for a better forward secrecy.
    Notes:
        Follow the same guidelines as in Question 2, but also note the following:

        - In order to deal with Diffie-Hellman aspect of this question, use the
            public (prime) modulus `HW9_helper.p_val`
        - When encoding/decoding integers, make sure to use "big-endian" encoding
        - Check Lecture 16, slide 31 to better understand the process, pay
            special attention to what value should be used as the key, and what
            value should be used as an input to the KDF
        - Make sure to only use the last 16-bytes of the KDF as the initial
            chain key, rather than the full output
        - Check the Signal specification (Section 2.3) here for more details:
            https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
    Args:
        public_component    (int):  The received D-H value A received from the
                                    other party.

        dh_secret           (int):  Your own D-H secret exponent b.

        init_root_key       (bytes): arbitrary length key to be used as the initial root key.

        msg_n               (int):  The order number of the message for which the
                                    key should be generated.
    Output:
        ret                 (bytes):  Hex-encoded 16-bytes message key that should
                                    be used to with the message number n.

    How to verify your solution:
    ```
        assert(q3_public_ratchet(10, 5, bytes.fromhex("00"*16), 10)  == b'\xabB\xd4\xe1\x96\xea\x9b\xd2x\xf3\xe5\xf8\xd3\x86p\xf4')
        assert(q3_public_ratchet(999999, 133333333333333337, bytes.fromhex("00"*10), 2)   == b'zJ\xbaA8Nb\x9c\xcc\x14`\xf6\x01]fi')
        assert(q3_public_ratchet(213214123, 1232, bytes.fromhex("99"*20), 1)   == b'\x0c\xf9\xd7\x06\xc0\xf4fu\xdf\xa3"\xa2\x15\xdd\xd0\xd1')
    ```
    """
    dh_output = pow(public_component, dh_secret, HW9_helper.p_val)
    h = HMAC.new(init_root_key, digestmod=SHA256)
    dh_output = dh_output.to_bytes((dh_output.bit_length() + 7) // 8, 'big')
    h.update(dh_output)
    chain_key = h.digest()[16:]
    return q2_symmetric_ratchet(chain_key, msg_n)


import networkx as nx

i = 0
test = []
with open('new_edges.txt', encoding='utf-8') as f:
    for line in f:
        pair = line.split('\t')
        pair[1] = pair[1][0:-1]
        pair = tuple(pair)
        i+=1
        test.append(pair)
        print(pair,i)
G = nx.Graph()
for pair in test:
    if G.has_edge(pair[0],pair[1]) == False:
        G.add_edge(pair[0],pair[1])
print(G.number_of_edges())
print(len(test))
