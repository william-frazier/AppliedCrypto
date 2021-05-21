#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from Cryptodome.Util.strxor import strxor

from sample_cipher import Sample_Cipher
from binascii import unhexlify, hexlify

def add_pkcs_pad(msg, block_size):
    """Adds PKCS#7 padding to an arbitrary length message based on the 'block_size'
    Args:
        msg  (bytes): ascii-encoded bytestring
    Output:
        ret  (bytes): padded message with length a multiple of block_size 
    """
    missing_len = block_size - (len(msg) % block_size)

    if (missing_len == 0):
        return msg + bytes([block_size]) * block_size
    else:
        return msg + bytes([missing_len]) * missing_len


def remove_pkcs_pad(padded_msg, block_size):
    """Removes PKCS#7 padding if it exists and returns the un-padded message
    Args:
        padded_msg  (bytes): padded message with length a multiple of block_size
    Output:
        ret         (bytes): un-padded message if the padding is valid, None otherwise 
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

    if pad_len == 0:
        return None

    # padding value is greater than the total message length
    if pad_len > padded_msg_len:
        return None

    # Where the padding starts on input message
    pad_start = padded_msg_len - pad_len

    # Check the ending values for the correct pad value
    if pad_start > 0:
        for char in padded_msg[padded_msg_len:pad_start-1:-1]:
            if char != pad_len:
                return None
    else:
        for char in padded_msg:
            if char != pad_len:
                return None

    # remove the padding and return the message
    return padded_msg[:pad_start]


def enc_cbc_mode(key, message, iv, cipher=Sample_Cipher()):
    ''' Args:
            key        (bytes): hex-encoded bytestring
            message    (bytes): ascii-encded bytestring
            iv         (bytes): hex-encoded bytestring

        Output:
            ciphertext (bytes): hex-encoded bytestring
    '''
    def slice_into_blocks(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE = cipher.BLOCK_SIZE

    msg_blocks = slice_into_blocks(
        add_pkcs_pad(message, BLOCK_SIZE), BLOCK_SIZE)

    ciphertext = ""

    for block in msg_blocks:
        block_input = strxor(unhexlify(iv), block)
        ciphertext_i = cipher.encipher(key.decode(), hexlify(block_input).decode())
        ciphertext += ciphertext_i
        iv = ciphertext_i.encode()
    return ciphertext.encode()


def dec_cbc_mode(key, ciphertext, iv, cipher=Sample_Cipher()):
    ''' Args:
            key        (bytes): hex-encoded bytestring
            ciphertext (bytes): hex-encded bytestring
            iv         (bytes): hex-encoded bytestring

        Output:
            message    (bytes): ascii-encoded bytestring
    '''
    def slice_into_block(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE_HEX = cipher.BLOCK_SIZE * 2
    BLOCK_SIZE = cipher.BLOCK_SIZE

    assert(len(ciphertext) % BLOCK_SIZE_HEX == 0)

    msg_blocks = slice_into_block(ciphertext, BLOCK_SIZE_HEX)

    plaintext = b""
    for block in msg_blocks:
        cipher_output = cipher.decipher(key.decode(), block.decode())
        plaintext_i = strxor(unhexlify(iv), unhexlify(cipher_output.encode()))
        plaintext += plaintext_i
        iv = block
    return remove_pkcs_pad(plaintext, BLOCK_SIZE)
