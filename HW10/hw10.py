
# -*- coding: utf-8 -*-

##################################### HW10 #####################################

"""
List you collaborators here:
                                party one 
                                party two...
Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""


import hw10_helper

# Helper libraries you may or may not need to use in your code
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from binascii import hexlify, unhexlify

def q1_sponge_aes_function(inputString, outputLen, r):
    """
    Question 1: Build a sponge function from AES
    
    The *sponge function* design is the basis of the SHA-3 hash function (aka
    Keccak). See the following for a reminder of its implementation:
    https://en.wikipedia.org/wiki/Sponge_function#/media/File:SpongeConstruction.svg
    - taken from Wikipedia).
    
    The sponge construction requires a public, fixed-length, random-looking
    permutation `f`. Since we haven't yet discussed in class how the actual
    Keccak-`f` function works, in this problem let's instead use in its place
    AES-128 with a publicly hardcoded key `K = "AES w/ fixed key"` (but without
    the quotes).
    
    Your Task:
        Your function should 'absorb' an arbitrary-length 'inputString'
        (interpreted as raw bytes) and then 'squeeze' out 'outputLen' bytes of data.
        
        Your sponge function should use AES with key `K` as the permutation `f`.
        You should split its 16-byte state into a rate of `r` bytes followed by 
        a capacity of `16-r` bytes.
    
    Notes:
        Don't worry about padding; that is, you may assume that inputs are
        always a multiple of `r` bytes in length.
        Keep in mind that the `r + c = 16`, so the capacity size is always the 
        remaining of the rate size.
        
    Args:
        inputString     (bytes):  ASCII-encoded string of an arbitrary-length
                                  (multiple of `r` bytes).
        outputLen       (int):    Number of output bytes that you should
                                  'squeeze' out of the input.
        r               (int):    Rate size (in bytes) of the the Sponge function
        
    Output:
        ret             (bytes):  Hex-encoded string of length 'outputLen'-bytes
                                  that you 'squeeze-out' of the sponge-function.
                                
    How to verify your solution:
    ```
        assert(q1_sponge_aes_function(b"this is a test message to be passed to be hashed", 10, 12) == b"45045a7eac2202857573")
        assert(q1_sponge_aes_function(b"the length of this message is a multiple of the 6 byte sponge rate", 10, 3) == b"5369b87b739347ed9e47")
        assert(q1_sponge_aes_function(b"the length of this message is a multiple of the 6 byte sponge rate", 10, 6) == b"0d8d8a67d52925badb92")
        assert(q1_sponge_aes_function(b"the length of this message is a multiple of the 6 byte sponge rate", 30, 6) == b"0d8d8a67d52925badb92698527cac836204f78cf6b92bcc90a63a21d4fa5")
    ```
    """
    
    key = b'AES w/ fixed key'
    cipher = AES.new(key, AES.MODE_ECB)
    pad_length = 16 - r
    capacity = b'\x00' * pad_length
    i = 0
    input_string = b'\x00' * r
    while inputString[i*r:(i+1)*r] != b'':
        input_string = strxor(input_string, inputString[i*r:(i+1)*r])
        output = cipher.encrypt(input_string + capacity)
        input_string = output[:r]
        capacity = output[r:]
        i+= 1
    final_output = output[:r]
    while len(final_output) < outputLen:
        output = cipher.encrypt(output)
        final_output += output[:r]
    return hexlify(final_output[:outputLen])



def q2_difference_propagation(Sbox):
    """
    Question 2: Constructing a difference propagation table

    In this problem, you must write the code to produce a difference propagation
    table like the one shown in lecture.

    Your Task:
    Construct this function to return the difference propagation table
    corresponding to a particular `Sbox` (where the input is a 2-dimensional
    list the represents an 8-bit Sbox).

    Notes:
    Remember that the difference propagation table is a 0-indexed 256 x 256
    matrix where each entry is in the range 0-256.
    The matrix is constructed as follows:
    the value in the (d_in, d_out) entry equals the number of pairs of inputs
    and outputs (x, y= S(x)) and (x', y' = S(x')) such that
    x XOR x' = d_in and y XOR y' = d_out (i.e., the difference of inputs is d_in
    and the difference of outputs is d_out).

    Your code must work for any 8-bit S-box that we provide as input.

    Your returned table should be a 2d-array (rather than a 1d-list) that you 
    can index as follows:
    ```
        val = table[r][c]
    ```
    
    Args:
    Sbox  (func(int):int): An S-Box substitution function that takes in an
                           integer input (value from 0-255) and returns an integer
                           output (value from 0-255)
                           (check hw10_helper.test_sbox as an example)
                    
    Output:
    ret   (list(list(int))): The difference propagation table as a 256 x 256
                             matrix where each entry is in the range 0-256
                             
    Test Vector:
    ```
      assert(q2_difference_propagation(hw10_helper.test_Sbox) == hw10_helper.test_diff_prop_table)
    ```
    """
    
    val = []
    for k in range(256):
        val.append([0]*256)
    for i in range(256):
        for j in range(256):
            i_val = Sbox(i)
            d_in = i ^ j
            j_val = Sbox(j)
            d_out = i_val ^ j_val
            val[d_in][d_out] += 1
    return val

