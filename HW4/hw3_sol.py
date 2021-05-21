#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

from sample_cipher import Sample_Cipher
from string import printable
from random import choices

def add_pkcs_pad(msg, block_size):
    """Adds PKCS#7 padding to an arbitrary length message based on the 'block_size'
    Args:
        msg  (str): ascii-encoded string  
    ret(bytes/bytearray): padded message with length a multiple of block_size 
    """
    missing_len = block_size - (len(msg) % block_size)

    if (missing_len == 0):
        return msg.encode('ascii') + bytes([block_size]) * block_size
    else:
        return msg.encode('ascii') + bytes([missing_len]) * missing_len


def remove_pkcs_pad(padded_msg, block_size):
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


def q1_enc_cbc_mode(key, message, iv, cipher=Sample_Cipher):
    """Question 1 (part 1): Implement CBC Mode encryption (with PKCS#7 padding, using the provided block cipher `cipher`)
        Before starting to implement this function, take a look at the CBC mode in the lecture slides. Also note that
        your CBC mode implementation should accept an arbitrary length message, and should pad the message according to the block
        size of the `cipher` method provided (cipher.BLOCK_SIZE).
        For the padding scheme, we will use the PKCS#7 standard. The PKCS#7 padding standard is a common method to pad messages 
        to a multiple of the block length. Let's take AES as an example, in which case the block length is 16 bytes.
        Given a string `s` that is n bytes short of being a multiple of the block length, PKCS#7 padding simply adds n bytes each 
        of which have the byte value n. 
        For instance, the string
            `TEST STRING`
        is 11 characters long and thus needs 5 bytes of padding. So, it gets padded to the string:
            `TEST STRING\x05\x05\x05\x05\x05`
        Here, the "\x05" denotes the byte value 5 in hex form (this is valid Python syntax, by the way).
        If we choose to use padding, then we must **always** do so because the person on the other end of the wire is 
        planning to remove the padding. In particular, if the string length is already a multiple of the block length, 
        then we must add a new block and fill it with padding.
        For instance, the 16-byte string
            `A COMPLETE BLOCK`
        gets PKCS#7 padded to the following 32-byte string:
            `A COMPLETE BLOCK\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`
        where "\x10" denotes the hex value 10 (i.e., decimal value 16, the block length).
        I recommend implementing the following methods first to help you implement the CBC mode
            - `pad(msg, block_size)`
                should take an input of arbitrary length and return a padded string based on the block_size 
                and following the PKCS#7 standard.
            - `unpad(padded_msg, block_size)`
                should remove the padding from the padded_msg and return the original un-padded message.
            You can use the examples above as test vectors for your padding implementation
    Your Task:
        This question has two parts, part one is the function `q1_enc_cbc_mode` that encrypts message under CBC, and the
        function `q1_dec_cbc_mode` that decrypts under CBC.
    Args:
        key     (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        message (str):      ascii input string with an arbitrary length
        iv      (str):      hex-encoded string of an IV that should be used for the CBC encryption (cipher.BLOCK_SIZE long)
        cipher  (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.encipher(message, key)
    Output:
        ret     (str):  hex-encoded ciphertext (don't return the IV as part of the ciphertext)
    Test vectors:
        q1_enc_cbc_mode(key="a8c0eeef71c4f0ad7942cb2eefb0dff0", message="w)0EA@W`j-3O~FhxwS~OixkV$D<2'v[apPoW[", iv="45054c1d141b6ae136b45c37800c7840", cipher=Sample_Cipher()) == "100ea146471f4ddc46fb829f6d9d5518229e2961bece0661d61656c2e989e157856b2cda53b8a46b308d5bba38934961"
        q1_enc_cbc_mode(key="68cf01cdb03ca97d1312b9e106c64ab4", message=",}54KK:'W,X-LAQ6P\/%aw70>~{Om~sqPu!_S=PeUlSx{_ID-&lcc\_RqgcFY|aeS", iv="8bdcc6f47a583fdf18d14dbac639bc6a", cipher=Sample_Cipher()) == "e250881abc2938ea59cd28d96268162f3fe125448c968d2181203e1407b65f33adf66a3b18b43b6fd54af1bcdcd3009af30fc4e7af741474ba67484eea3fbb07804575f27a9c9e1237c802011784f1d1"
        q1_enc_cbc_mode(key="77ea003e2f1c5911af304ac2faa638cc", message="g@$Q?qX(YK*Zqp`C>z0|4<ZeCzUuF$6Bhbk?|k%?Xoc%F[dxb|6ix=QYoL)8.,;E", iv="922687e8d2e82ef1bc11b5dab6e7913b", cipher=Sample_Cipher()) == "648e0a290a8b4cf9793249eedd61e541af988041ad7edd4c858cfb0915b7d1469020e937941d6bbbef56ffea29706545e0a49eee01f7a21cbad59408ae8b0b8760b219849d13b0b5c4d6c195e1811ef5"
        q1_enc_cbc_mode(key="534641668f7d38aeaccd8d6233a22411", message="-P-y3", 	    iv="8cdd421f93b855d3d27066223a3fa872", cipher=Sample_Cipher()) == "da5970059af60b9631836cd144323354"
        q1_enc_cbc_mode(key="74deb9f94977bcfeac492e5b399a5c0c", message="4j:lTdvCrB", 	iv="cd32ccc8339ec87e7eec2ccc46c31182", cipher=Sample_Cipher()) == "299a3db5782acbd04cdddcda8f55efc8"
    """

    def slice_into_blocks(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE = cipher.BLOCK_SIZE

    msg_blocks = slice_into_blocks(
        add_pkcs_pad(message, BLOCK_SIZE), BLOCK_SIZE)

    ciphertext = ""
    iv_bytes = bytes.fromhex(iv)

    for block in msg_blocks:
        block_input = strxor(iv_bytes, block)
        ciphertext_i = cipher.encipher(key, block_input.hex())
        ciphertext += ciphertext_i
        iv_bytes = bytes.fromhex(ciphertext_i)
    return ciphertext


def q1_dec_cbc_mode(key, ciphertext, iv, cipher=Sample_Cipher):
    """Question 1 (part 2): Implement CBC Mode **decryption** (with PKCS#7 padding, using the provided block cipher `cipher`)
    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs
    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (multiple cipher.BLOCK_SIZE-bytes long)
        iv          (str):      hex-encoded string of an IV that should be used for the CBC decryption (cipher.BLOCK_SIZE-bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.decipher(ciphertext, key)
    Output:
        ret     (str):          ascii output string with an arbitrary length (with the padding removed)
    Test vectors:
        You can use the same test vectors from `q1_enc_cbc_mode` in the reverse order to double check your solution
    """

    def slice_into_block(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE = cipher.BLOCK_SIZE
    ciphertext = bytes.fromhex(ciphertext)
    assert(len(ciphertext) % BLOCK_SIZE == 0)

    msg_blocks = slice_into_block(ciphertext, BLOCK_SIZE)

    plaintext = b""
    for block in msg_blocks:
        cipher_output = cipher.decipher(key, block.hex())
        print(cipher_output)
        plaintext_i = strxor(bytes.fromhex(iv), bytes.fromhex(cipher_output))
        plaintext += plaintext_i
        iv = block.hex()
    print(plaintext)
    return remove_pkcs_pad(plaintext, BLOCK_SIZE).decode('ascii')


def q2_enc_ctr_mode(key, message, nonce, cipher=Sample_Cipher):
    """Question 2 (part 1): Implement Counter (CTR) Mode encryption (using the provided block cipher `cipher`)
    Your Task:
        Before starting to implement this function, take a look at the CTR mode in the lecture slides. This question has two parts, 
        part one is the function `q2_enc_ctr_mode` that encrypts under CTR, and the function `q2_dec_ctr_mode` that decrypts under CTR.     
    Note:
        You can assume that the BLOCK_SIZE is at least 4 bytes, so the nonce you get as an input will always have a length
        of 4 bytes less than the BLOCK_SIZE of the cipher given. So make sure to append a counter of size 4 bytes to your nonce
        when using it. You can also assume that we would never  the counter to go up to UINT32_MAX (0xFFFFFFFF).    
    Args:
        key     (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        message (str):      ascii input string with an arbitrary length
        nonce   (str):      hex-encoded string of a nonce that should be used for the CTR encryption (cipher.BLOCK_SIZE - 4bytes long)
        cipher  (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.encipher(message, key)
    Output:
        ret     (str):  hex-encoded ciphertext (arbitrary length)
    Test vectors:
        q2_enc_ctr_mode(key="99cd2b776f71f87e87c8cb9ccf8bcbe4", message=":.DU|C61RtcUj[km)<6", nonce="fd7ed96cbfa3f7369a964fee", cipher=Sample_Cipher()) == "e08ee68d6387b81d71e4f7892fedbfe0f39c94"
        q2_enc_ctr_mode(key="88d1104f7bd5661768ac72f3d5a453b7", message="u+V[nN#m0YLwOuKp%u!:@5|e4v]22'ukkx};(_,cdm5>5VZsmqE7)W(O-&/!Y?lhhF", nonce="5633e2712a3684784cf1a6c5", cipher=Sample_Cipher()) == "e062cfa6c48addd26eb976819998f56eb03cb8c7eaf182da6a9667c4e4cacb92fe31e4c6829bd2dc3a8d0fc8e3bbe411f838dcca8393d6f073c615d78fd2d252fd0f"
        q2_enc_ctr_mode(key="2e7d7d855f802fcf06166adc10650c79", message="I6IC$d|Tb|5H~^7.U9:<N!Y}y6$M_i;)", nonce="4709acbfea6811fb62379f13", cipher=Sample_Cipher()) == "9ed90a46ae7fe1832797b91ea476c5e182d67939c43ac4aa3cdda81b8541c9ec"
        q2_enc_ctr_mode(key="4c55061b9e3d802b64897306af2389a1", message="qeN",	  nonce="a7314e0f243701914bf02b08", cipher=Sample_Cipher()) == 	"d4731a"
        q2_enc_ctr_mode(key="7b2937e962319e03aec2d26c8d681e06", message="}9&|:WQ",nonce="a5466611ff4369a8267ebd60", cipher=Sample_Cipher()) == 	"1bb8c0d40626a7"
    """

    def slice_into_block(message, block_size):
        len_message = len(message)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE = cipher.BLOCK_SIZE
    COUNTER_SIZE = 4  # bytes, from the question

    msg_blocks = slice_into_block(message, BLOCK_SIZE)

    ciphertext = ""
    counter = 0
    for block in msg_blocks:
        new_counter = nonce + ('%0{}x'.format(COUNTER_SIZE * 2) % counter)
        one_pad = cipher.encipher(key, new_counter)
        block_len = len(block)
        ciphertext_i = strxor(block[:block_len].encode(
            'ascii'), bytes.fromhex(one_pad)[:block_len])
        ciphertext += ciphertext_i.hex()
        counter += 1
    return ciphertext


def q2_dec_ctr_mode(key, ciphertext, nonce, cipher=Sample_Cipher):
    """Question 2 (part 2): Implement Counter (CTR) Mode **decryption** (using the provided block cipher `cipher`)
    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs
    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (arbitrary length)
        nonce       (str):      hex-encoded string of a nonce that should be used for the CTR decryption (cipher.BLOCK_SIZE - 4bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                    +   cipher.encipher(ciphertext, key)
    Output:
        ret     (str):          ascii output string with an arbitrary length
    Test vectors:
        You can use the same test vectors from `q2_enc_ctr_mode` in the reverse order to double check your solution
    """

    def slice_into_block(message, block_size):
        len_message = len(message)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]

    BLOCK_SIZE = cipher.BLOCK_SIZE
    COUNTER_SIZE = 4  # bytes, from the question

    ciphertext = bytes.fromhex(ciphertext)

    msg_blocks = slice_into_block(ciphertext, BLOCK_SIZE)

    plaintext = b""
    counter = 0

    for block in msg_blocks:
        new_counter = nonce + ('%0{}x'.format(COUNTER_SIZE * 2) % counter)
        one_pad = cipher.encipher(key, new_counter)
        block_len = len(block)
        plaintext_i = strxor(
            block[:block_len], bytes.fromhex(one_pad)[:block_len])
        plaintext += plaintext_i
        counter += 1
    return plaintext.decode('ascii')