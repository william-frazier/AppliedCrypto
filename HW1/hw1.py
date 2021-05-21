#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def bytes_to_int(string_byte):
    """ Convert from a Python byte object to a list of integers, where each integer
    represents the value of the corresponding byte of the string. As a result,
    the length of the output list should equal the length of the input string.

    Example test cases:

        b"test" -> [116, 101, 115, 116]
        b"this is a test" -> [116, 104, 105, 115, 32, 105, 115, 32, 97, 32,
        116, 101, 115, 116]

    """
    lst = []
    for i in range(len(string_byte)):
        lst.append(string_byte[i])
    return lst


def int_byte_to_hex(single_char):
    """ Read a single, decimal byte from the user and return a string of its
    hexidecimal value. This string should use lowercase and should always be
    exactly two characters long. Make sure you pad the beginning with a 0 if
    necessary, and make sure the string does NOT start with '0x'.

    Example test cases:

        255 -> "ff"
        10 -> "0a"
        65 -> "41"
        161 -> "a1"
    """
    val = hex(single_char)[-2:]
    if val[0] == 'x':
        val = '0' + val[1]
    return val


def int_bytes_to_hex(the_input):
    """ Take in a list of bytes, separated by a space, and return a hex string
    corresponding to the list of bytes. The easiest way to do this is by using
    your solution to the previous question.

    Example test case: [1, 10, 100, 255] -> "010a64ff"

    """
    val = ''
    for i in the_input:
        val += int_byte_to_hex(i)
    return val


def hex_string_to_bytes(the_input):
    """ Take in a hex string and convert it to a list of bytes.
    (This should effectively "undo" the question 3.)

    Example test case: "70757a7a6c65" -> [112, 117, 122, 122, 108, 101]
    """
    lst = []
    i = 0
    while i < len(the_input):
        lst.append(int(the_input[i:i+2], 16))
        i += 2
    return lst


def int_bytes_to_byte_object(the_input):
    """ Take in a list of bytes, and return the string (in bytes) they
    correspond to. Unlike the prior question, here you should return a
    raw bitstring and not the hex values of the bytes! As a result,
    the output need not always be printable.
    (This should effectively "undo" the question 1.)

    Example test case: [116, 101, 115, 116] -> b"test"
    """
    return bytes(the_input)


def string_to_hexstring(the_input):
    """ Take in a string(byte object), and return the hex string of the bytes
    corresponding to it. While the hexlify() command will do this for you,
    we ask that you instead solve this question by combining the methods
    you have written so far in this assignment.

    Example test case: b"puzzle" -> "70757a7a6c65"
    """

    # I thought this took a byte object but gradescope is using a string so 
    # I handle both cases here
    if type(the_input) == str:
        the_input = bytes(the_input.encode())
    return int_bytes_to_hex(bytes_to_int(the_input))


def hexstring_to_byte_object(the_input):
    """  Now take in a hex string and return the string that it corresponds to.
    (This should effectively "undo" question 6.) Once again, the unhexlify()
    command will do this for you, but you should instead solve this question
    using only the code you have written so far in this assignment.

    Example test case: "70757a7a6c65" -> b"puzzle"

    """
    return int_bytes_to_byte_object((hex_string_to_bytes(the_input)))


def one_time_pad_encrypt(pt, k):
    from Cryptodome.Util.strxor import strxor
    """ Given a plaintext in bytes pt, and key k in bytes.
    Compute and return the ciphertext c where c = (pt xor k).

    Example test case:
        one_time_pad_encrypt(b'I like applied crypto',
        b'9\x1a\xda\t-\x9e\x08\xf5\xf5W\x84.\x1a\xa3\xda\x1ec\xe0\xee\xc8#') ->
        b'\xdeP\xd7mBO\xc6G\xc0'\xe9\xb0<\xce}9\xeb\xd3u\x81\xf7'

    """
    return strxor(pt,k)


def sha256_hexoutput(the_input):
    import hashlib
    """ Given input in string format, compute the SHA-256 hash value of the
    input and return the response as a hex string. (Keep this code handy!
    In future assignments, we might provide you with the SHA-256 hash of
    the answer so you can check your solution against it.)

    Example test cases:

        "test" -> "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        "testing" -> "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90"
        You can actually type "sha256 blah" into DuckDuckGo to get the value
        of sha-256(blah)

    """
    m = hashlib.sha256()
    m.update(the_input.encode())
    return string_to_hexstring(m.digest())
