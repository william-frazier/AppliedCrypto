#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## HW 2 ##################################################################


"""
List you collaborators here:
                                party one 
                                party two...
Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""


from Cryptodome.Util.strxor import strxor
from sample_cipher import Sample_Cipher
from binascii import hexlify, unhexlify


def pad(msg, block_size):
    overflow = len(msg) % block_size
    if overflow == 0:
        padding = chr(block_size) * block_size
#    elif overflow == 9:
#        padding = "\x99" * 9
#    elif overflow == 10:
#        padding = "\x0a" * 10
#    elif overflow == 13:
#        padding = "\x0d" * 13
    else:
        overflow = block_size - overflow
        padding = chr(overflow) * overflow
    return msg + padding

def unpad(padded_msg, block_size):
    if padded_msg[-1:] == "t":
        amount_padding = 18
    elif padded_msg[-1:] == "n":
        amount_padding = 20
    elif padded_msg[-1:] == "r":
        amount_padding = 26
    else:
        amount_padding = ord(unhexlify(padded_msg[-2:])) * 4
    msg = padded_msg[:-(amount_padding)]
    return msg

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
                                +   cipher.encipher(key, message)
    Output:
        ret     (str):  hex-encoded ciphertext (don't return the IV as part of the ciphertext)
    Test vectors:
        q1_enc_cbc_mode(key="a8c0eeef71c4f0ad7942cb2eefb0dff0", message="w)0EA@W`j-3O~FhxwS~OixkV$D<2'v[apPoW[", iv="45054c1d141b6ae136b45c37800c7840", cipher=Sample_Cipher()) == "100ea146471f4ddc46fb829f6d9d5518229e2961bece0661d61656c2e989e157856b2cda53b8a46b308d5bba38934961"
        q1_enc_cbc_mode(key="68cf01cdb03ca97d1312b9e106c64ab4", message=",}54KK:'W,X-LAQ6P\/%aw70>~{Om~sqPu!_S=PeUlSx{_ID-&lcc\_RqgcFY|aeS", iv="8bdcc6f47a583fdf18d14dbac639bc6a", cipher=Sample_Cipher()) == "e250881abc2938ea59cd28d96268162f3fe125448c968d2181203e1407b65f33adf66a3b18b43b6fd54af1bcdcd3009af30fc4e7af741474ba67484eea3fbb07804575f27a9c9e1237c802011784f1d1"
        q1_enc_cbc_mode(key="77ea003e2f1c5911af304ac2faa638cc", message="g@$Q?qX(YK*Zqp`C>z0|4<ZeCzUuF$6Bhbk?|k%?Xoc%F[dxb|6ix=QYoL)8.,;E", iv="922687e8d2e82ef1bc11b5dab6e7913b", cipher=Sample_Cipher()) == "648e0a290a8b4cf9793249eedd61e541af988041ad7edd4c858cfb0915b7d1469020e937941d6bbbef56ffea29706545e0a49eee01f7a21cbad59408ae8b0b8760b219849d13b0b5c4d6c195e1811ef5"
        q1_enc_cbc_mode(key="534641668f7d38aeaccd8d6233a22411", message="-P-y3", 	iv="8cdd421f93b855d3d27066223a3fa872", cipher=Sample_Cipher()) == "da5970059af60b9631836cd144323354"
        q1_enc_cbc_mode(key="74deb9f94977bcfeac492e5b399a5c0c", message="4j:lTdvCrB", 	iv="cd32ccc8339ec87e7eec2ccc46c31182", cipher=Sample_Cipher()) == "299a3db5782acbd04cdddcda8f55efc8"
    """

    message = pad(message, cipher.BLOCK_SIZE)
    message = message.replace("\t", "\x09")
    message = message.replace("\n", "\x0a")
    message = message.replace("\r", "\x0d")

    blocks = len(message) / cipher.BLOCK_SIZE
    i = 0
    encrypted_message = ""
    message = bytes(message.encode())
    while i < blocks:
        message_section = message[i*(cipher.BLOCK_SIZE):(i+1)*cipher.BLOCK_SIZE]
        message_section = str(hexlify(message_section))[2:-1]
        message_section = hex(int(message_section, 16) ^ int(iv, 16))[2:]
        if len(message_section) % 2 != 0:
            message_section = '0' + message_section
        enc = cipher.encipher(key, message_section)
        iv = enc
        encrypted_message += enc
        i+=1
    
    while "\\" in encrypted_message:
        index = encrypted_message.index("\\")
        encrypted_message = encrypted_message[:index] + encrypted_message[index+1:]
    while "\'" in encrypted_message:
        index = encrypted_message.index("\'")
        encrypted_message = encrypted_message[:index] + encrypted_message[index+1:]
    if len(encrypted_message) % 2 != 0:
        encrypted_message = "0" + encrypted_message
    return encrypted_message


def q1_dec_cbc_mode(key, ciphertext, iv, cipher=Sample_Cipher):
    """Question 1 (part 2): Implement CBC Mode **decryption** (with PKCS#7 padding, using the provided block cipher `cipher`)
    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs
    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (multiple cipher.BLOCK_SIZE-bytes long)
        iv          (str):      hex-encoded string of an IV that should be used for the CBC decryption (cipher.BLOCK_SIZE-bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.decipher(key, ciphertext)
    Output:
        ret     (str):          ascii output string with an arbitrary length (with the padding removed)
    Test vectors:
        You can use the same test vectors from `q1_enc_cbc_mode` in the reverse order to double check your solution
    """

    blocks = len(ciphertext)/(2*cipher.BLOCK_SIZE)
    i = 0
    padded_message = ''
    while i < blocks:
        message_section = ciphertext[i*(2*cipher.BLOCK_SIZE):(i+1)*(2*cipher.BLOCK_SIZE)]
        dec = cipher.decipher(key, message_section)
        if i == 0:
            dec = strxor(unhexlify(dec), unhexlify(iv))
        else:
            c_prev = ciphertext[(i-1)*(2*cipher.BLOCK_SIZE):i*(2*cipher.BLOCK_SIZE)]
            dec = strxor(unhexlify(dec), unhexlify(c_prev))
        i+=1
        padded_message += str(dec)[2:-1].replace("\\\\","\\").replace("\\\'","\'")
    message = unpad(padded_message, cipher.BLOCK_SIZE)
    return message


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
                                +   cipher.encipher(key, message)
    Output:
        ret     (str):  hex-encoded ciphertext (arbitrary length)
    Test vectors:
        q2_enc_ctr_mode(key="99cd2b776f71f87e87c8cb9ccf8bcbe4", message=":.DU|C61RtcUj[km)<6", nonce="fd7ed96cbfa3f7369a964fee", cipher=Sample_Cipher()) == "e08ee68d6387b81d71e4f7892fedbfe0f39c94"
        q2_enc_ctr_mode(key="88d1104f7bd5661768ac72f3d5a453b7", message="u+V[nN#m0YLwOuKp%u!:@5|e4v]22'ukkx};(_,cdm5>5VZsmqE7)W(O-&/!Y?lhhF", nonce="5633e2712a3684784cf1a6c5", cipher=Sample_Cipher()) == "e062cfa6c48addd26eb976819998f56eb03cb8c7eaf182da6a9667c4e4cacb92fe31e4c6829bd2dc3a8d0fc8e3bbe411f838dcca8393d6f073c615d78fd2d252fd0f"
        q2_enc_ctr_mode(key="2e7d7d855f802fcf06166adc10650c79", message="I6IC$d|Tb|5H~^7.U9:<N!Y}y6$M_i;)", nonce="4709acbfea6811fb62379f13", cipher=Sample_Cipher()) == "9ed90a46ae7fe1832797b91ea476c5e182d67939c43ac4aa3cdda81b8541c9ec"
        q2_enc_ctr_mode(key="4c55061b9e3d802b64897306af2389a1", message="qeN",	  nonce="a7314e0f243701914bf02b08", cipher=Sample_Cipher()) == 	"d4731a"
        q2_enc_ctr_mode(key="7b2937e962319e03aec2d26c8d681e06", message="}9&|:WQ",nonce="a5466611ff4369a8267ebd60", cipher=Sample_Cipher()) == 	"1bb8c0d40626a7"
    """
    
    counter = "00000000"
    enc_message = ""
    blocks = len(message) / cipher.BLOCK_SIZE
    i = 0
    message = hexlify(bytes(message.encode()))
    while i < blocks:
        enc = cipher.encipher(key, nonce + counter)
        temp = hex(int(counter, 16)+1)[2:]
        while len(temp) < 8:
            temp = "0" + temp
        counter = temp
        message_section = message[i*(2*cipher.BLOCK_SIZE):(i+1)*(2*cipher.BLOCK_SIZE)]
        cipher_text = hex(int(enc[:len(message_section)],16) ^ int(message_section,16))[2:]
        if len(cipher_text) % 2 != 0:
            cipher_text = "0" + cipher_text
        enc_message += cipher_text
        i += 1
    
    return enc_message


def q2_dec_ctr_mode(key, ciphertext, nonce, cipher=Sample_Cipher):
    """Question 2 (part 2): Implement Counter (CTR) Mode **decryption** (using the provided block cipher `cipher`)
    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs
    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (arbitrary length)
        nonce       (str):      hex-encoded string of a nonce that should be used for the CTR decryption (cipher.BLOCK_SIZE - 4bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                    +   cipher.encipher(key, ciphertext)
    Output:
        ret     (str):          ascii output string with an arbitrary length
    Test vectors:
        You can use the same test vectors from `q2_enc_ctr_mode` in the reverse order to double check your solution
    """
    
    counter = "00000000"
    enc_message = ""
    blocks = len(ciphertext) / (2*cipher.BLOCK_SIZE)
    i = 0
    while i < blocks:
        enc = cipher.encipher(key, nonce + counter)
        temp = hex(int(counter, 16)+1)[2:]
        while len(temp) < 8:
            temp = "0" + temp
        counter = temp
        message_section = ciphertext[i*(2*cipher.BLOCK_SIZE):(i+1)*(2*cipher.BLOCK_SIZE)]
        cipher_text = hex(int(enc[:len(message_section)],16) ^ int(message_section,16))[2:]
        while len(cipher_text) != len(message_section):
            cipher_text = "0" + cipher_text
        enc_message += cipher_text
        i += 1
    return str(unhexlify(enc_message))[2:-1].replace("\\\\","\\").replace("\\\'","\'")
