#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 6 ##################################################################

"""
List you collaborators here:
                                party one
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import HW6_helper
from binascii import unhexlify
from Crypto.Cipher import AES
#from Crypto.Util.Padding import unpad



def q1_encrypt_mac(enc_key, hmac_key, blob):
    """Question 1: Encrypt-then-MAC

    In Lecture 12, we discussed the difference in behavior between MAC-then-Encrypt
    and Encrypt-then-MAC. We concluded that the latter was the better way to
    protect + authenticate data in transit because the former was plagued by the
    fact that the receiver might try to decrypt data before verifying that it
    comes from the correct source.

    The scenario:
        In this problem, you will take on the role of Bob. Assume that Alice sends
        you messages that follow the Encrypt-then-MAC paradigm.
        That is: Alice first encrypts her messages using AES in CBC mode with
        PKCS#7 padding, and then she MACs the message using HMAC-SHA1.

        You (Bob) possess both the `aes-key` and the `hmac-key`.


    Your Task:
        Construct the verify-then-decrypt routine for Bob to use in order to
        validate and then read messages sent by Alice. You should parse the blob
        sent by Alice in the following way:

        the first 16 bytes are the IV for CBC mode, the last 20 bytes are the
        HMAC-SHA1 tag, and everything in the middle is the CBC ciphertext
        corresponding to the padded message.

        Your function should return the correct message if it was properly
        Encrypted-then-MAC'd, or it should output the string 'ERROR' (without the quotes)
        if there is an issue. (You may assume that Alice will never send you the
        string ERROR intentionally.)

    Args:
        enc_key     (bytes):  16-bytes hex-encoded key to be used for AES
        hmac_key    (bytes):  20-bytes hex-encoded key to be used for HMAC
        blob  (bytes):  arbitrary-length hex-encoded data (ciphertext)
    Output:
        ret         (str):  ASCII-encoded, unpadded message (or 'ERROR' if there
                            is a problem with the input blob invalid)
    Test vectors:
        assert(q1_encrypt_mac(  b'7369787465656e2062797465206b6579',
                                b'7477656e74792062797465206c6f6e67206b6579',
                                (b'00000000000000000000000000000000a70c430ebf35441874ac9f758c59ee10e931378c49507b45b278f922db372a682e13bf25')) == 'valid message')

        assert(q1_encrypt_mac(  b'7369787465656e2062797465206b6579',
                                b'7477656e74792062797465206c6f6e67206b6579',
                                (b'00000000000000000000000000000000a70c430ebf'
                                b'35441874ac9f758c59ee10e931378c49507b45b278'
                                b'f922db372a682e13bf34')) == 'ERROR') #1-byte change
    """

    iv = blob[:32]
    ciphertext = blob[32:-40]
    tag = blob[-40:]
    true_tag = HW6_helper.hmacsha1(unhexlify(hmac_key), unhexlify(iv+ciphertext))
    if true_tag == tag.decode('ascii'):
        iv = unhexlify(iv)
        enc_key = unhexlify(enc_key)
        ciphertext=unhexlify(ciphertext)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        if pt == None:
            return "ERROR"
        pt = pt.decode('ascii')
        return pt
    return "ERROR"
 
    

def unpad(padded_msg, block_size):
    """Removes PKCS#7 padding if it exists and returns the un-padded message
    Args:
        padded_msg  (bytes/bytearray)  
    ret(bytes/bytearray): un-padded message if the padding is valid, None otherwise 
    """
    padded_msg_len = len(padded_msg)
    # Check the input length
    if padded_msg_len == 0:
        return None

    # Checks if the input is not a multiple of the block length
    if (padded_msg_len % block_size):
        return None

    # Last byte has the value
    pad_len = padded_msg[-1]

    # padding value is greater than the total message length
    if pad_len > padded_msg_len:
        return None

    # Where the padding starts on input message
    pad_start = padded_msg_len-pad_len

    # Check the ending values for the correct pad value
    for char in padded_msg[padded_msg_len:pad_start-1:-1]:
        if char != pad_len:
            return None

    # remove the padding and return the message
    return padded_msg[:pad_start]


def q2_cbc_key_reuse(ciphertext, tag):
    """
    The scenario:
    You are a big time hacker who has been intercepting messages between Bob and Alice. Bob and
    Alice are using Encrypt-and-MAC composed of both CBC encryption and CBC-MAC.
    In this question, you do not need to decrypt/authenticate their messages, you just need to make
    a ciphertext that passes their authentication.


    Your Task:
    Create a program that takes in a Ciphertext that was made using THE SAME KEY for encyption with CBC and
    message authentication CBC-MAC. Both CBC-ENC and CBC-MAC are being done on the PLAINTEXT. Your function
    should simply return a byte object that is DIFFERENT from the original, but can be authenticated using
    the key that Bob and Alice have. The IV used for this question will be all 0s.
    For further clarity, I'd recommend looking at HW6_helper.


    Args:
        ciphertext (bytes): Ciphertext made using CBC-ENC (with IV=0) and CBC-MAC, with the same key
        tag (bytes): Tag of ciphertext

    output:
        ret (bytes): New Ciphertext that will pass the CBC-MAC verification check with the same (unknown) key



    Test Vectors:
        HW6_helper.test_q2(q2_cbc_key_reuse)
    """
    pad = b'\x00' * 16
    return pad + ciphertext
    


# The following question is extra credit, worth an extra 5 points. You do not have to complete it.
def q3_harder_cbc_key_reuse(plaintext, iv, ciphertext, tag):
    """
    The scenario:
    Just like question 2, Alice and Bob are communicating using Enc-and-MAC using CBC for
    encryption and CBC-MAC for authentication, with a reused key. There are just two changes.
    
    1. Alice and Bob are guaranteed to choose an initial plaintext that is 1 block long
    even after padding, and you are provided the plaintext.

    2. The IV used in CBC encryption is nonzero, and you are also provided with this IV.
    (By contrast, CBC-MAC never has an IV.)


    Your Task:
    Conduct a forgery attack, just as before. That is, you must construct a new tuple
    (newIV, newCiphertext, newTag) such that newTag passes the MAC verification check.
    

    Args:
        plaintext  (bytes): Plaintext fed as input to both CBC-ENC and CBC-MAC
        iv         (bytes): IV for CBC encryption mode (remember that CBC-MAC doesn't have an IV)
        ciphertext (bytes): CBC-encrypted ciphertext of the Plaintext and IV
        tag        (bytes): CBC-MAC tag Tag of ciphertext

    output:
        newIV         (bytes): A new 16-byte long IV of your choice
        newCiphertext (bytes): A new ciphertext of your choice
                               (should be multiple of the block length)
        newTag        (bytes): A 16-byte long tag of your choice. Your answer is correct
                               if and only if the MAC verification test passes.



    Test Vectors:
        HW6_helper.test_q3(q3_harder_cbc_key_reuse)
    """
    

    newCiphertext = tag
    iv = b'\x00' * 16
    return (iv, newCiphertext, newCiphertext)
