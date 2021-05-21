#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## HW 2 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below.
The specification of each of the functions is commented out,
and an example test case is provided for your convenience.
"""

# Feel free to use either of `Cryptodome` or `cryptography`

from Cryptodome.Util.strxor import strxor
from hw2_helper import Encipher, three_letter_words, words
import os, hw1_sol
from binascii import hexlify, unhexlify


def find_key(plaintext, ciphertext):
    """ Given a plaintext and a ciphertext, find the 16-bytes key that
        was used under AES (ECB mode) to produce the given ciphertext.

    Args:
        plaintext (bytes): bytes object of length 16.
        ciphertext (bytes): hexlified bytes object of length 32.

    Returns:
        key: hex-encoded 16-bytes key used to produce 'ciphertext'
        given 'plaintext' under AES (ECB-mode)
    
    Note:
        Keep in mind that AES keys are 128-bits (16 bytes), and you
        should assume for this question that the first **108-bits**
        of the AES key are all zeros.

    Hint:
        1. Use brute-force!
        2. Use the Encipher function imported and
           refer to hw2_helper.py on how to use AES!

    Examples:
        find_key(b'hello worldworld', b'6f7fc801114754bcd671cfc2e3ebff31') == "00000000000000000000000000000001"
        find_key(b'hello worldworld', b'73d5f04fca50f5186c36bdf8aedb902d') == "0000000000000000000000000000d7f6"
        find_key(b'hello worldworld', b'bc249c288f9f9468295330ecb49c8236') == "0000000000000000000000000001dae9"
      """
    
    assert(type(plaintext) == bytes)
    assert(type(ciphertext) == bytes)
    for i in range(128):
        for j in range(256):
            for k in range(256):
                key = hw1_sol.int_bytes_to_byte_object([0,0,0,0,0,0,0,0,0,0,0,0,0,i,j,k]).hex()
                outcome = Encipher(plaintext, key)
                if outcome == ciphertext:
                    return bytes(key.encode())
    print("No key found.")



def toy_twotimepad(c1, c2):
    """A one-time pad simply involves the xor of a message with
       a key to produce a ciphertext: c = m ^ k.
       It is essential that the key be as long as the message,
       or in other words that the key not be repeated for
       two distinct message blocks.
       
       In this problem, you'll be cracking small two-time-pad examples.
       The input ciphertexts are created by taking two random 3-letter
       words from the set of the 100 most common English words:
       https://en.wikipedia.org/wiki/Most_common_words_in_English 
       (You can find the list three_letter_words imported from hw2_helper.py
       for your convenience) and apply one time pad to both with the same
       key k. Your job is to recover the two inital messages, and return 
       them in a tuple.

    Input:
        c1, c2 (byte objects): Ciphertexts created by xor-ing a 3-letter
                               word with some random 3-letter key

    Return:
        {m1, m2}: A set of two strings found within the words list in
                  hw2_helper.py 

    Examples:
        toy_twotimepad(b'\x1e\x1b\x03', b'\x0f\t\x1f') ==  {"day", "use"}
        toy_twotimepad(strxor(b'and', b'aaa'), strxor(b'not', b'aaa')) ==  {"and", "not"}
        toy_twotimepad(strxor(b'all', b'xyz'), strxor(b'any', b'xyz')) ==  {"all", "any"}

    """
    diff = strxor(c1,c2)
    pair = set()
    for word in three_letter_words:
        for other_word in three_letter_words:
            if strxor(bytes(word.encode()), bytes(other_word.encode())) == diff:
                pair.add(word)
                pair.add(other_word)
                return pair



def two_time_pad2(c1_hex, c2_hex):
    """In this problem you will again break a cipher
       when the one-time pad is re-used.
       You are given two hex-encoded ciphertext inputs c1_hex and c2_hex
       with the same length that were formed by applying a “one-time pad” to
       two different messages with the same key.
       Find the two corresponding messages m_1 and m_2.
       Do not try brute-force the key since autograder will time out.
    
    Okay, to make your search simpler, let me lay out a few ground rules.
    1. Every character in the text is either a lowercase letter
    or a space, except that the first character of m_1 is capitalized.
    No punctuation appears in the messages. 
    2. Each message consists of English words in ASCII
    separated by spaces. However, the second message m_2 starts with a space.
    3. All of the words within each message is guaranteed to come from
    the same set of the 100 most common English words:
    https://en.wikipedia.org/wiki/Most_common_words_in_English.
    (You can find the list words imported from hw2_helper.py
    for your convenience)

    Args:
        c1_hex, c2_hex: hex-encoded ciphertext
        
    Returns:
        Output the concatenation of strings m_1 and m_2.

    Test Vector:
    two_time_pad_random('c1727f30cda9d57ffc63bb0af8','ad75712d88e5c87bb934ad17e6')
    Look
     have
    (You get partial credit if you find answer to this test vector.)
    """
    print(c1_hex)
    print(c2_hex)
    c1_hex = str(c1_hex)[2:-1]
    c2_hex = str(c2_hex)[2:-1]
    diff = strxor(hw1_sol.int_bytes_to_byte_object(hw1_sol.hex_string_to_bytes(c1_hex)),hw1_sol.int_bytes_to_byte_object(hw1_sol.hex_string_to_bytes(c2_hex)))
    next_letter = str(diff)[2]
    
    c1 = ''
    c2 = ''
    for word in words:
        if word[0] == next_letter:
            word = word.capitalize()
            word += " "
            for other_word in words:
                c2_first_word = " "
                c2_first_word += other_word + " "
                encoding = strxor(bytes(word.encode()[:len(c2_first_word)]), bytes(c2_first_word[:len(word)].encode()))
                if encoding in diff[:len(encoding)]:
                    c1 = word
                    c2 = c2_first_word
                    next_letter = str(diff[len(encoding):])[2].lower()

    while encoding != diff:
        if len(c2) - len(c1) == 1:
            [c1_new, c2_new] = first_letter(c1, c2, next_letter, diff)
            c1 = c1_new + " "
            c2 = c2_new + " "
            encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
            next_letter = str(diff[len(encoding):])[2].lower()
        elif  len(c1) - len(c2) == 1: 
            [c1_new, c2_new] = first_letter_flip(c1, c2, next_letter, diff)
            c1 = c1_new + " "
            c2 = c2_new + " "
            encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
            next_letter = str(diff[len(encoding):])[2].lower()
        
        elif encoding[:-1] == diff:
            return c1[:-1] + c2[:-1]
        elif len(c1) > len(c2):
            [c2_new, c1_new] = some_random(c2, c1, diff)
            c1 = c1_new 
            c2 = c2_new + " "
            encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
            next_letter = str(diff[len(encoding):])[2].lower()
        elif len(c1) < len(c2):
            [c1_new, c2_new] = some_random(c1, c2, diff)
            c1 = c1_new + " "
            c2 = c2_new
            encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
            next_letter = str(diff[len(encoding):])[2].lower()
        elif len(c1) == len(c2) and encoding != diff:
            [c1_new, c2_new] = total_random(c1, c2, diff)
            c1 = c1_new + " "
            c2 = c2_new + " "
            encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
            next_letter = str(diff[len(encoding):])[2].lower()
    
        else:       
            return "error"

    return encoding
    
        
    
def first_letter(c1, c2, first_letter, diff):
    print("call fl")
    for word in words:
        if word[0] == first_letter:
            temp = c1
            temp += word
            for other_word in words:
                temp2 = c2
                temp2 += other_word
                encoding = strxor(bytes(temp.encode()[:len(temp2)]), bytes(temp2[:len(temp)].encode()))
                if encoding in diff[:len(encoding)]:
                    c1 = temp 
                    c2 = temp2
                    new_encoding = encoding
                    first_letter = str(diff[len(new_encoding):])[2].lower()
    return [c1, c2]


def first_letter_flip(c1, c2, first_letter, diff):
    print("call flf")
    c1_new = ' '
    c2_new = ' '
    for word in words:
        if word[0] == first_letter:
            temp = c2
            temp += word
            for other_word in words:
                temp2 = c1
                temp2 += other_word
                encoding = strxor(bytes(temp.encode()[:len(temp2)]), bytes(temp2[:len(temp)].encode()))
                if encoding in diff[:len(encoding)]:
                    c1_new = temp2
                    c2_new = temp
                    if encoding == diff:
                        return [c1_new, c2_new]
    return [c1_new, c2_new]

def word_known(c1, c2, diff):
    print("call wk")
    c2_new = ' '
    for word in words:
        temp2 = c2
        temp2 += word
        encoding = strxor(bytes(c1.encode()[:len(temp2)]), bytes(temp2.encode()[:len(c1)]))
        if encoding in diff[:len(encoding)]:
            c2_new = temp2
            if encoding == diff:
                return [c1, c2_new]
    return [c1, c2_new]

def word_known_flip(c1, c2, diff):
    print("call wkf")
    c1_new = ' '
    for word in words:
        temp = c1
        temp += word
        encoding = strxor(bytes(temp.encode()[:len(c2)]), bytes(c2.encode()[:len(temp)]))

        if encoding in diff[:len(encoding)]:
            c1_new = temp
            if encoding == diff:
                return [c1_new, c2]
    return [c1_new, c2]

def total_random(c1, c2, diff):
    print("call tr")
    c1_new = ' '
    c2_new = ' '
    for word in words:
        temp = c2
        temp += word
        for other_word in words:
            temp2 = c1
            temp2 += other_word
            encoding = strxor(bytes(temp.encode()[:len(temp2)]), bytes(temp2[:len(temp)].encode()))

            if encoding in diff[:len(encoding)]:
                c1_new = temp2
                c2_new = temp
                if encoding == diff:
                    return [c1_new, c2_new]
    return [c1_new, c2_new]

def some_random(c1, c2, diff):
    print("call sr")
    c1_new = ' '
    c2_new = ' '
    for word in words:
        temp2 = c1
        temp2 += word
        encoding = strxor(bytes(temp2.encode()[:len(c2)]), bytes(c2[:len(temp2)].encode()))
        if encoding in diff[:len(encoding)]:
            c1_new = temp2
            if encoding == diff:
                return [c1_new, c2]
    return [c1_new, c2]


def two_time_pad(c1_hex, c2_hex):
    c1_hex = str(c1_hex)[2:-1]
    c2_hex = str(c2_hex)[2:-1]
    diff = strxor(hw1_sol.int_bytes_to_byte_object(hw1_sol.hex_string_to_bytes(c1_hex)),hw1_sol.int_bytes_to_byte_object(hw1_sol.hex_string_to_bytes(c2_hex)))
    next_letter = str(diff)[2]
    
    c1 = ''
    c2 = ''
    for word in words:
        if word[0] == next_letter:
            word = word.capitalize()
            word += " "
            for other_word in words:
                c2_first_word = " "
                c2_first_word += other_word + " "
                encoding = strxor(bytes(word.encode()[:len(c2_first_word)]), bytes(c2_first_word[:len(word)].encode()))
                if encoding in diff[:len(encoding)]:
                    c1 = word
                    c2 = c2_first_word
                    next_letter = str(diff[len(encoding):])[2].lower()
    if len(c2) - len(c1) == 1:
        [c1_new, c2_new] = first_letter(c1, c2, next_letter, diff)
        c1 = c1_new + " "
        c2 = c2_new + " "
        encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
        next_letter = str(diff[len(encoding):])[2].lower()
    if len(c1) - len(c2) == 1: 
        [c1_new, c2_new] = first_letter_flip(c1, c2, next_letter, diff)
        c1 = c1_new + " "
        c2 = c2_new + " "
        encoding = strxor(bytes(c1.encode()[:len(c2)]), bytes(c2[:len(c1)].encode()))
        next_letter = str(diff[len(encoding):])[2].lower()
        
    encoding_length = len(diff)
    c1_poss = set()
    c2_poss = set()
    if len(c1) == encoding_length:
        c1_poss.add(c1)
    if len(c2) == encoding_length:
        c2_poss.add(c2)
    if len(c1[:-1]) == encoding_length:
        c1_poss.add(c1[:-1])
    if len(c2[:-1]) == encoding_length:
        c2_poss.add(c2[:-1])
    for word in words:
        temp = c1 + word + " "
        temp2 = c2 + word + " "
        if len(temp[:-1]) == encoding_length:
            c1_poss.add(temp[:-1])
        if len(temp2[:-1]) == encoding_length:
            c2_poss.add(temp2[:-1])
        for other_word in words:
            temp_2 = other_word
            temp2_2 = other_word
            if len(temp + temp_2) == encoding_length:
                c1_poss.add(temp + temp_2)
            if len(temp2 + temp2_2) == encoding_length:
                c2_poss.add(temp2 + temp2_2)
            for final_word in words:
                temp_3 = " " + final_word
                temp2_3 = " " + final_word
                if len(temp + temp_2 + temp_3) == encoding_length:
                    c1_poss.add(temp + temp_2 + temp_3)
                if len(temp2 + temp2_2 + temp2_3) == encoding_length:
                    c2_poss.add(temp2 + temp2_2 + temp2_3)
    for phrase in c1_poss:
        for other_phrase in c2_poss:
            encoding = strxor(bytes(phrase.encode()), bytes(other_phrase.encode()))
            if encoding == diff:
                return phrase + other_phrase
                    
    