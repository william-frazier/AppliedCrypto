#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## HW 4 ##################################################################


"""
List your collaborators here:
                                party one 
                                party two...
Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""


from Cryptodome.Util.strxor import strxor
from sample_cipher import Sample_Cipher
from binascii import hexlify, unhexlify

def q1_padding_oracle(ciphertext, iv=b"00"*16, key=b"00"*16):
    #key=b"00"*16
    #b"a8c0eeef71c4f0ad7942cb2eefb0dff0"
    """ Question 1: Pretend you are writing code for an server. Upon recieving a
            message encrypted with CBC mode, your server must decrypt this message
            and strip its padding before affirming to the client that it has recieved
            the message correctly. You find that you must ensure that the padding has
            been done correctly, according to the PKCS#7 standard, before stripping the
            message, or else your padding strip function won't work properly. Thus,
            you've decided to create a simple padding oracle function that will return
            True to the client if the padding is fine and can be stripped from the message,
            or else return False if the padding has been done incorrectly.

            You may assume that the server is using the following values when decrypting
            the recieved ciphertext using CBC mode:
            
            key = b"00000000000000000000000000000000"
            iv  = b"00000000000000000000000000000000"
            cipher = Sample_Cipher()
            
            (This server is not very good at picking keys or IVs.)
            
        Your task:
            Implement a padding oracle to return whether or not the recieved ciphertext
            has been padded correctly after decryption. (Hint: you will likely want to
            use a modified version of the dec_cbc_mode() function from last week's
            homework to complete this task).

        Args:
            ciphertext   (bytes):  hex-encoded ciphertext bytestring
            iv           (bytes):  hex-encoded iv bytestring
            key          (bytes):  hex-encoded key bytestring

        Output:
            ret           (bool):  True if the decrypted ciphertext has been padded correctly
                                   False if the decrypted ciphertext has not been padded correctly

        Test Vectors:
            q1_padding_oracle(enc_cbc_mode(key=b"00000000000000000000000000000000", message = b'524d5050a8b7f5a8405043fdf2f2f2f2', iv=b"00000000000000000000000000000000", cipher=Sample_Cipher()))==True
            q1_padding_oracle(b'83b7fba840404dfb9250b6b751ef43438e66b9a63fc3b2b8e696e7c85b1e6e6e')==True
            q1_padding_oracle(b'2fa892b7fba840404dfb9250b6b751ef')==False
            q1_padding_oracle(b'83b7fba840404dfb9250b6b751ef43438e66b9a63fc')==False
    """

    ciphertext = ciphertext.decode('ascii')
    if len(ciphertext) % 16 != 0:
        return False
    key = key.decode('ascii')
    message = my_oracle(key=key,ciphertext=ciphertext, iv=iv.decode('ascii'), cipher=Sample_Cipher())
    
    return message

#q1_enc_cbc_mode(key="a8c0eeef71c4f0ad7942cb2eefb0dff0", message="w)0EA@W`j-3O~FhxwS~OixkV$D<2'v[apPoW[", iv="45054c1d141b6ae136b45c37800c7840", cipher=Sample_Cipher()) == "100ea146471f4ddc46fb829f6d9d5518229e2961bece0661d61656c2e989e157856b2cda53b8a46b308d5bba38934961"

def q2_padding_oracle_attack(iv, ciphertext, oracle):
    """ Question 2: Now pretend you are Eve, and have happened to find the server
            function from question 1. You've decided to intercept encrypted messages, and
            use the padding oracle in order to decrypt them.

            NOTE: Although you may know the key used in the Q1 oracle, we will be testing
                  your function against our own oracle, using a completely different key.
                  Therefore, simply decrypting and stripping your message according to the
                  key given to you in Q1 will NOT work in the testing environment. Instead,
                  you should be thinking about how the padding oracle leaks information
                  about the inputted ciphertext in order to find the original message.
                  
        Your task:
            Use the leaky padding oracle you just created in order to decrypt the given ciphertext
            byte by byte.
            
        Args:
            iv                          (bytes):  hex-encoded iv bytestring
            ciphertext                  (bytes):  hex-encoded ciphertext bytestring
            oracle      (ciphertext -> boolean):  a padding oracle which accepts some ciphertext
                                                  and returns True if padded correctly, and
                                                  False otherwise
        Output:
            message                     (bytes):  ascii-encoded input bytestring with an arbitrary length
                                                  (with the padding removed)

        Test Vectors:
            q2_padding_oracle_attack(b"524d5050a8b7f5a8405043fdf2f2f2f2", q1_padding_oracle))==b"Hello world!"
            q2_padding_oracle_attack(b'53ef4343f99f85b7a840effb504d8fb7235ef7fbdb87e990e052940d6a6e1708', q1_padding_oracle))==b"Padding oracles are fun!"
            q2_padding_oracle_attack(enc_cbc_mode(key=b"00000000000000000000000000000000", b"some message", iv=b"00000000000000000000000000000000", cipher=Sample_Cipher()), q1_padding_oracle))==b"some message"
            q2_padding_oracle_attack(enc_cbc_mode(key=b"00000000000000000000000000000000", b"some other message", iv=b"00000000000000000000000000000000", cipher=Sample_Cipher()), q1_padding_oracle))==b"some other message"
            q2_padding_oracle_attack(iv=b'c8a121f1f32034bb2b3e65bc173b3b0e', ciphertext=b'bb975ec19cdbc1b0668dbfb2a44d95e4',oracle=q1_padding_oracle)      == b'rXw'
            q2_padding_oracle_attack(iv=b'45054c1d141b6ae136b45c37800c7840', ciphertext=b"100ea146471f4ddc46fb829f6d9d5518229e2961bece0661d61656c2e989e157856b2cda53b8a46b308d5bba38934961", oracle=q1_padding_oracle)
    message="w)0EA@W`j-3O~FhxwS~OixkV$D<2'v[apPoW["
    """
    
    message = b''
    i = 1
#    print(ciphertext)
    iters = len(ciphertext)/32
    while i < iters:
        new_iv = ciphertext[-64:-(32)]
        block = ciphertext[-32:]
        block = block[:32]
#        print(new_iv)
#        print(block)
        message = padding_attack_block(iv=new_iv,ciphertext=ciphertext, oracle=oracle, block_num=1) + message
        i += 1
        ciphertext = ciphertext[:-32]
#    print("iv=",iv)
#    print(ciphertext)
    
    temp = padding_attack_block(iv=iv, ciphertext=ciphertext, oracle=oracle, block_num=-1)

    temp = strxor(unhexlify(temp), unhexlify(iv))
    message = temp + message

#    print("here",temp)
#    print("above")
#    print(message)
    message = remove_pkcs_pad(message, 16)
#    print(message)
    return message
    
    
def padding_attack_block(iv, ciphertext, oracle, block_num):
    
  
#    alter = -17
    alter = 15
    found_yet = False
    count = 1
    val_array = []
    message = b""
    current_pos = 1
    altered_ciphertext = ciphertext
    val_total = b""
    while found_yet == False:
        val = hexlify(count.to_bytes(1,"big"))
#        if val_total == b'0' * len(val_total) and current_pos != 1:
#            next_val = hexlify((1+current_pos).to_bytes(1,"big"))
#            print("1",next_val)
#            next_val = hexlify(strxor(next_val, hexlify(current_pos.to_bytes(1,'big'))))[-2:]
#            print("2",next_val)
#            val_total = next_val * (current_pos-1)
#            print(val_total)      
        count += 1
        val = val + val_total
        ending = altered_ciphertext[-32:]
        ending = ending[:32]
        altered_ciphertext = b'00'*alter + val + ending
#        altered_ciphertext = altered_ciphertext[:alter*2] + val + altered_ciphertext[alter*2+2:]
        if altered_ciphertext != ciphertext:
            if oracle(y=iv, x=altered_ciphertext):
                
#                print(val, current_pos)
#                print("iv=",iv,"alt_c=",altered_ciphertext)
                if len(ciphertext) == 32:
                    match = strxor(unhexlify(val), unhexlify(ciphertext[-len(val):]))
                else:
                    match = strxor(unhexlify(val), unhexlify(ciphertext[-32-len(val):-32]))
#                print("val=",val[:2])
                val_positionless = strxor(unhexlify(val[:2]), current_pos.to_bytes(1,"big"))
#                print("val_pos", val_positionless)
                # val_pos stores output of dec
                encoded_pos = current_pos.to_bytes(1,"big")
#                print("match=", match)
                if block_num == 1:
                    byte = strxor(match[:1], encoded_pos)
                    message = byte + message
                else:
                    byte = hexlify(strxor(unhexlify(val[:2]), encoded_pos))
#                    print("yeet",byte)
#                    print("pos=", encoded_pos)
                    message = byte + message

                val_array.append(val_positionless)
#                print(val_array)
                current_pos += 1
                val_total = b''
                for found in val_array[::-1]:
                    val_total += hexlify(strxor(found, current_pos.to_bytes(1,"big"))) 
                
#                print("!!!!!!!!!!!!!!!", val_total)
#                print(byte)
                
#                altered_ciphertext = altered_ciphertext[:alter*2] + val + altered_ciphertext[alter*2+2:]
                alter -= 1
                
                
                
                count = 0
                

        if count == 255:
            return message
        











def q3_enc_cbc_with_cts(key, message, iv, cipher=Sample_Cipher()):
    """ Question 3 (Part 1): Now that we've analyzed how vulnerable padded ciphertext can
            be when we are relying on leaky padding oracles, let's look at how to circumvent
            this potential issue! One solution is to use ciphertext stealing rather than
            message padding. For this problem, you'll be implementing the CBC mode of encryption
            using CTS.

            NOTE: Given the nature of CTS, this function will ONLY be used to encrypt messages
                that have a length greater than the length of the Sample_Cipher block. Therefore,
                your function will not be tested against messages with lengths less than or equal
                to the size of one block.
            
        Your task:
            This question has two parts, part one is the function `q3_enc_cbc_with_cts` that
            encrypts a message under CBC using CTS, and the function `q3_dec_cbc_with_cts` that
            decrypts under CBC using CTS.

        Args:
            key       (bytes):      hex-encoded bytestring (cipher.BLOCK_SIZE-bytes long)
            message   (bytes):      ascii-encoded input bytestring with an arbitrary length
            iv        (bytes):      hex-encoded string of an IV that should be used for the CBC encryption (cipher.BLOCK_SIZE long)
            cipher   (Cipher):      Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                        +   cipher.encipher(key, message)
                                        
        Output:
            ret       (bytes):      hex-encoded ciphertext bytestring (don't return the IV as part of the ciphertext)
            
        Test Vectors:
            q3_enc_cbc_with_cts(key=b"a8c0eeef71c4f0ad7942cb2eefb0dff0", message=b"Hello world hello world hello world", iv=b"45054c1d141b6ae136b45c37800c7840", cipher=Sample_Cipher())== b"ae2065e416d2a58b5efac63c2a85c0769536a6f5ba933605263a14237e7bb182517a5e"
            q3_enc_cbc_with_cts(key=b"68cf01cdb03ca97d1312b9e106c64ab4", message=b"This is a message", iv=b"8bdcc6f47a583fdf18d14dbac639bc6a", cipher=Sample_Cipher()) == b"2332683ba7329c00649091d63a858e05c1"
            q3_enc_cbc_with_cts(key=b"77ea003e2f1c5911af304ac2faa638cc", message=b"Ciphertext stealing is exciting!", iv=b"922687e8d2e82ef1bc11b5dab6e7913b", cipher=Sample_Cipher()) == b'53ec689069582286d0ccd4bdfd90d0d894af76273a8660986aeb22e965cc4b5a'
    """
    
    def slice_into_blocks(message, block_size):
        len_message = len(message)
        assert(len_message >= block_size)
        return [message[i: i + block_size] for i in range(0, len_message, block_size)]


    msg_blocks = slice_into_blocks(message, cipher.BLOCK_SIZE)
    iv_bytes = bytes.fromhex(iv.decode('ascii'))
    ciphertext = ''
    if len(message) % cipher.BLOCK_SIZE == 0:
        for block in msg_blocks:
            block_input = strxor(iv_bytes, block)
            print(block_input)
            ciphertext_i = cipher.encipher(key.decode('ascii'), block_input.hex())
            ciphertext += ciphertext_i
            iv_bytes = bytes.fromhex(ciphertext_i)
        return bytes(ciphertext.encode())

    num_blocks = len(message) // cipher.BLOCK_SIZE
    cut_length = len(message)
    if len(message) % cipher.BLOCK_SIZE != 0:
        num_blocks += 1
    while len(message) % cipher.BLOCK_SIZE != 0:
        message = message + b'\x00'
    if len(message[:-2*cipher.BLOCK_SIZE]) != 0:
        ciphertext += q1_enc_cbc_mode(key=key.decode('ascii'), message=message[:-2*cipher.BLOCK_SIZE].decode('ascii'), iv=iv.decode('ascii'), cipher=Sample_Cipher())
    # Confident that ciphertext is correct
        second_to_last = strxor(message[-2*cipher.BLOCK_SIZE:-cipher.BLOCK_SIZE], unhexlify(bytes(ciphertext[-2*cipher.BLOCK_SIZE:].encode())))
    else:
        second_to_last = strxor(message[-2*cipher.BLOCK_SIZE:-cipher.BLOCK_SIZE], unhexlify(iv))
#    second_to_last = hexlify(second_to_last)
    # if ciphertext is correct, second_to_last is correct

    
    
    
    
    enc_second_to_last = cipher.encipher(key.decode('ascii'), hexlify(second_to_last).decode('ascii'))
    
    

    temp = strxor(unhexlify(bytes(enc_second_to_last.encode())), unhexlify(hexlify(message[-cipher.BLOCK_SIZE:])))

    enc_last_block = q1_enc_cbc_mode(key=key.decode('ascii'), message=message[-cipher.BLOCK_SIZE:].decode('ascii'),iv=enc_second_to_last, cipher=Sample_Cipher())

    ciphertext += enc_last_block + enc_second_to_last

    return bytes(ciphertext[:2*cut_length].encode())

def q3_dec_cbc_with_cts(key, message, iv, cipher=Sample_Cipher()):
    """ Question 3 (Part 2): Implement the decryption of CBC mode with ciphertext stealing.

        Your task:
            The problem description is similar to the one in the previous problem, just note
            the different inputs and expected outputs.

        Args:
            key          (bytes):      hex-encoded bytestring (cipher.BLOCK_SIZE-bytes long)
            ciphertext   (bytes):      hex-encoded ciphertext bytestring (multiple cipher.BLOCK_SIZE-bytes long)
            iv           (bytes):      hex-encoded bytestring of an IV that should be used for the CBC decryption (cipher.BLOCK_SIZE-bytes long)
            cipher      (Cipher):      Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                        +   cipher.decipher(key, ciphertext)
                                        
        Output:
            ret          (bytes):      ascii-encoded output bytestring with an arbitrary length (with the padding removed)
            
        Test Vectors:
            You can use the same test vectors from `q3_enc_cbc_with_cts` in the reverse order to double check your solution.
            
    """
    
    
    num_blocks = len(message) // (2*cipher.BLOCK_SIZE)

    if len(message) % cipher.BLOCK_SIZE != 0:
        num_blocks += 1
    else:
        return bytes(q1_dec_cbc_mode(key=key.decode('ascii'),ciphertext=message.decode('ascii'), iv=iv.decode('ascii'),cipher=cipher).encode())
    ret = ''
    if len(message[:(num_blocks-2)*2*cipher.BLOCK_SIZE]) != 0:
        ret += q1_dec_cbc_mode(key=key.decode('ascii'), ciphertext=message[:(num_blocks-2)*2*cipher.BLOCK_SIZE].decode('ascii'), iv=iv.decode('ascii'), cipher=cipher)
        iv = message[(num_blocks-3)*2*cipher.BLOCK_SIZE:(num_blocks-2)*2*cipher.BLOCK_SIZE]
        print("iv=",iv)
    # Confident that ciphertext is correct
#        second_to_last = strxor(message[-2*cipher.BLOCK_SIZE:-cipher.BLOCK_SIZE], unhexlify(bytes(ret[-2*cipher.BLOCK_SIZE:].encode())))
    second_to_last_enc = message[(num_blocks-2)*2*cipher.BLOCK_SIZE:(num_blocks-1)*2*cipher.BLOCK_SIZE]

    second_to_last = cipher.decipher(key.decode('ascii'), unhexlify(second_to_last_enc.hex()).decode('ascii'))
    overflow = (2*cipher.BLOCK_SIZE) - (len(message) % (2*cipher.BLOCK_SIZE))
    print(second_to_last)
    print(second_to_last[-overflow:])
    reconstructed_sec = message[(num_blocks-1)*2*cipher.BLOCK_SIZE:] + bytes(second_to_last[-overflow:].encode())
    print(reconstructed_sec)
    final = strxor(unhexlify(reconstructed_sec),unhexlify(bytes(second_to_last.encode())))
    mid = cipher.decipher(key.decode('ascii'), unhexlify(reconstructed_sec.hex()).decode('ascii'))
    print(mid)
    mid = strxor(unhexlify(iv), unhexlify(bytes(mid.encode())))
    print(ret)
    print(mid)
    print(final)
    while b'\x00' == final[-1:]:
        final = final[:-1:]
    return bytes(ret.encode()) + mid+ final















    
def my_oracle(key, ciphertext, iv, cipher=Sample_Cipher()):
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


    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    msg_blocks = slice_into_block(ciphertext, BLOCK_SIZE)

    plaintext = b""
    for block in msg_blocks:
        cipher_output = cipher.decipher(key, block.hex())

        plaintext_i = strxor(bytes.fromhex(iv), bytes.fromhex(cipher_output))

        plaintext += plaintext_i
        iv = block.hex()
    return unpad_oracle(plaintext, BLOCK_SIZE)


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
    # Last byte has the value
    pad_len = padded_msg[-1]
    # Checks if the input is not a multiple of the block length
    if (padded_msg_len % block_size):
        return None



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

def unpad_oracle(padded_msg, block_size):
    rep = padded_msg[-1]
    i = 1
    if rep == 0:
        return False
    while i <= rep:
        if padded_msg[-i] != rep:
            return False
        i += 1
    return True



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


def add_pkcs_pad(msg, block_size):
    """Adds PKCS#7 padding to an arbitrary length message based on the 'block_size'
    Args:
        msg  (str): ascii-encoded string  
    ret(bytes/bytearray): padded message with length a multiple of block_size 
    """
    missing_len = block_size - (len(msg) % block_size)
    if len(msg) % block_size == 0:
        return msg.encode('ascii')
    if (missing_len == 0):
        return msg.encode('ascii') + bytes([block_size]) * block_size
    else:
        return msg.encode('ascii') + bytes([missing_len]) * missing_len



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
        print(block.hex())
        cipher_output = cipher.decipher(key, block.hex())
        plaintext_i = strxor(bytes.fromhex(iv), bytes.fromhex(cipher_output))
        plaintext += plaintext_i
        iv = block.hex()
    return plaintext.decode('ascii')


