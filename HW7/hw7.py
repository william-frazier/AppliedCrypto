#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## HW 7 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...
Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

from binascii import hexlify, unhexlify
from urllib.parse import urlparse
import random
import string
import hashlib
import hw7_helper
import os
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as hazmatAES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.backends import default_backend as backend



def q1_siv_mode_enc(enc_key, mac_key, plaintext, associated_data):
    """Question 1 (part 1): Synthetic Initialization Vector (SIV) Authenticated Encryption
    Your Task:
        Your function should implement the SIV mode for authenticated encryption.
        For this implementation, you would have to use the AES block cipher in CTR mode,
        along with CMAC as a MAC.
    Args:
        enc_key         (bytes):  16-bytes hex-encoded key to be used for AES
        mac_key         (bytes):  16-bytes hex-encoded key to be used for CMAC
        plaintext       (bytes):  arbitrary-length ASCII encoded plaintext
        associated_data (bytes):  arbitrary-length hex-encoded data to be 
                                    authenticated, but not encrypted
    Output:
        ret             (bytes):  hex-encoded, ciphertext formatted as
                                    tag + ciphertext 
    Test vectors:
        assert(q1_siv_mode_enc( enc_key=b"7f7e7d7c7b7a79787776757473727170", 
                        mac_key=b"404142434445464748494a4b4c4d4e4f",
                        plaintext=b"this is some plaintext to encrypt using SIV-AES",
                        associated_data = b"00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
                ) == b"2550eb1783787e5f2d4e56fba6dff0a7df554c297854c8c4e4833435e66989314b6b2791862c7d11498c2ef034bfbb63808c73bc5ea23e64cb58a8e1a5775a")
    Note:
        Also feel free to use componenets from the Cryptodome/cryptography libraries 
        to build this function (ex. `from Cryptodome.Hash import CMAC`). That being 
        said, you should not use the SIV mode provided by any library, you should 
        combine the building blocks to implement the SIV mode on your own.
        When using the tag as a nonce for the CTR mode, some CTR implementations
        would not allow the nonce to be equal to the block_size (for example, 
        the `Cryptodome.Cipher` class with throw an error when using a nonce
        of size > block_size - 1), so I recommend using the CTR mode provided by
        the library `cryptography` instead 
        (e.g `from cryptography.hazmat.primitives.ciphers import Cipher`).
        Also note that for this implementation, there's no need to clear any bits
        of the tag before using it as a nonce. You can assume that the number of
        blocks we would test against would not overflow the counter bits.
    """

    cobj = CMAC.new(key=unhexlify(mac_key), ciphermod=AES, msg=unhexlify(associated_data)+plaintext)
    tag = cobj.digest()
    hex_tag = hexlify(tag)
    cipher = Cipher(hazmatAES(unhexlify(enc_key)), CTR(tag), backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return hex_tag + hexlify(ct)


def q1_siv_mode_dec(enc_key, mac_key, ciphertext, associated_data):
    """Question 1 (part 2): Synthetic Initialization Vector (SIV) Authenticated Encryption
    Your Task:
        Similar to the first part of this question, your function should decrypt
        the output produced by the function in the first part and return the 
        plaintext if the tag is valid, and return ERROR otherwise.
    Args:
        enc_key         (bytes):  16-bytes hex-encoded key to be used for AES
        mac_key         (bytes):  16-bytes hex-encoded key to be used for CMAC
        ciphertext      (bytes):  arbitrary-length hec-encoded ciphertext (same format
                                as the output of q1_siv_mode_enc)
        associated_data (bytes):  arbitrary-length hex-encoded data to be 
                                authenticated, but not encrypted
    Output:
        ret             (bytes):  ASCII-encoded, plaintext (or 'ERROR')
    Test vectors:
        assert(q1_siv_mode_dec( enc_key=b"7f7e7d7c7b7a79787776757473727170", 
                        mac_key=b"404142434445464748494a4b4c4d4e4f",
                        ciphertext=b"2550eb1783787e5f2d4e56fba6dff0a7df554c297854c8c4e4833435e66989314b6b2791862c7d11498c2ef034bfbb63808c73bc5ea23e64cb58a8e1a5775a",
                        associated_data = b"00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
                ) == b"this is some plaintext to encrypt using SIV-AES")
        assert(q1_siv_mode_dec( enc_key=b"404142434445464748494a4b4c4d4e4f", 
                        mac_key=b"7f7e7d7c7b7a79787776757473727170",
                        ciphertext=
                            q1_siv_mode_enc(enc_key=b"404142434445464748494a4b4c4d4e4f", 
                                mac_key=b"7f7e7d7c7b7a79787776757473727170",
                                plaintext=b"here i am encrypting some more plaintext",
                                associated_data = b"baabaabaabaabaabaabaabaabaabaabaabaa"),
                        associated_data = b"baabaabaabaabaabaabaabaabaabaabaabaa"
                ) == b"here i am encrypting some more plaintext")
    """
    nonce = unhexlify(ciphertext[:32])
    cipher = Cipher(hazmatAES(unhexlify(enc_key)), CTR(nonce), backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(unhexlify(ciphertext[32:])) + decryptor.finalize()
    cobj = CMAC.new(key=unhexlify(mac_key), ciphermod=AES, msg=unhexlify(associated_data)+plaintext)
    tag = cobj.digest()
    if tag == nonce:
        return plaintext
    return 'ERROR'

def q2_length_extension_attack(tag, new_command, verify_func):
    """ Your Task: You are a malicious hacker that is conducting a
    man in the middle attack. You are intercepting traffic between
    alice and server_bob.
    You have your favorite packet sniffer opened up and you captured
    the following GET request going from alice to server_bob:
    "http://www.bob_server.com/users/api?tag_user=tag&user=alice&command1=hex(getitems)".

    Note that server_bob accepts commands as hex-encoded strings, which
    we informally in the URL above using the term "hex". To be concrete:
    if alice wants to send the command "getitems", then she really sends
    the string hexlify(b"getitems").decode()
    Bob's server will then unhexlify any command that it receives.

    In this problem, you will take on the role of Mallory. Your task is
    to impersonate Alice on Bob's server. you are tasked to query Bob
    with arbitrary new commands. In theory, this should be easy as
    sending the following GET request:
    "http://www.bob_server.com/users/api?tag_user=tag&user=alice&command1=hex(getitems)&command2=hex(new_command)".

    However, server_bob has deployed a security measure specifically
    for this case. server_bob stops random people from injecting
    different commands by checking the tag field in the GET request.
 
    server_bob is aware of the cryptographic doom principle, so
    it only process the commands if the tag is valid.

    server_bob is generating the tag object in the following way:
    tag = sha256(password_alice || command1=hex(getitems) || command2=hex(new_command)).

    Since you don't know the password of alice, the only way to send
    new commands is to forge a valid new tag. Luckily for you, sha256
    uses the Merkle-Damgard construction and is vulnerable to
    Length extension attacks. (Bob forgot to use sHMAC, which would have
    protected the above construction against length extension.)

    Use the length extension attack to forge new tags and run arbitrary
    commands of your choice. In the helper file you will see an implementation
    of sha256 in python3. Feel free to use the helper file as pleased.

    Args:
        tag                     (str) : tag used to authenticate the request.
        new_command             (str) : new command to be executed.
	verify_func	(str -> bool) : function that takes a url and tells you if the url is 
					valid or not. It's just the verify function with a password 						already set.
					Look at the section "How to generate your own test vector". 
    Outout:
        ret                     (str) : Forged get request

    Note: you may assume the length of alice's password is between 1 and 32
    printable characters.

    How to generate your own test vectors:

    def verify(url, password):
        password = password.encode()

        query = urlparse(url).query.split('&')
        tag = query[0].split('=')[1]

        command1 = query[2].split("=")
        command1 = command1[0].encode() + b'=' + unhexlify(command1[1].encode())

        command2 = query[3].split("=")
        command2 = command2[0].encode() + b'=' + unhexlify(command2[1].encode())
        calculated_tag = hashlib.sha256(password + command1 + command2).hexdigest()
        return calculated_tag == tag


    random_string_function = lambda x: ''.join([random.choice(string.printable) for i in range(random.randint(1, x))])
    secret = random_string_function(32)
    tag = hashlib.sha256((secret + "command1=getitems").encode()).hexdigest()
    new_com
    mand = random_string_function(32)
    forged_query = q2_length_extension_attack(tag, new_command, lambda x: verify(x, secret))
    assert verify(forged_query, secret)
    """
    get_padding = b'command1=getitems0'
    while len(get_padding) < 300:
#        new_tag = hw7_helper.sha256(b"tag" + padding + bytes(new_command.encode()))
#        message = tag + padding + 'command1=getitems' + new_command
        padding = hw7_helper.pad_message(get_padding)[-1][len(get_padding)%64:]
#        if verify_func(message):
#            print("hit")
        com1 = hexlify(b"getitems"+padding).decode()
#        print("com1=", com1)
        
        compress = hw7_helper.pad_message(get_padding + padding+ b'command2='+new_command.encode())[-1]
#        print("compress=",compress)
#        print("used",get_padding)
        new_tag = hw7_helper.compression_function(tag.encode(), compress)
#        print("tag=",new_tag)
#        print("com2=", new_command.encode())
        message = "http://www.bob_server.com/users/api?tag_user=" + new_tag + "&user=alice&command1=" + com1 + "&command2=" + hexlify(new_command.encode()).decode()
        
        if verify_func(message):
            print("success!!")
            return message
        get_padding += b'0'
#    print(message)
#    print(new_command)



#def verify(url, password):
#    password = password.encode()
#    query = urlparse(url).query.split('&')
#    tag = query[0].split('=')[1]
#    
#    command1 = query[2].split("=")
#    command1 = command1[0].encode() + b'=' + unhexlify(command1[1].encode())
##    print("final1 =",command1)
#    command2 = query[3].split("=")
#    command2 = command2[0].encode() + b'=' + unhexlify(command2[1].encode())
#
#    calculated_tag = hashlib.sha256(password + command1 + command2).hexdigest()
#    return calculated_tag == tag
#
#
#random_string_function = lambda x: ''.join([random.choice(string.printable) for i in range(random.randint(1, x))])
#secret = random_string_function(32)
##print(secret.encode())
#tag = hashlib.sha256((secret + "command1=getitems").encode()).hexdigest()
#hw7_helper.sha256((secret + "command1=getitems").encode())
#
##print(tag)
##print(hw7_helper.pad_message((secret + "command1=getitems").encode()))
#new_command = random_string_function(32)
#forged_query = q2_length_extension_attack(tag, new_command, lambda x: verify(x, secret))

#assert verify(forged_query, secret)