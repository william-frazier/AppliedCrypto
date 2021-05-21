
# This file is provided for you to help with your implementation, DON'T submit this file.
# ONLY submit `HW6.py`

from Cryptodome.Util.strxor import strxor
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Hash import HMAC
from Cryptodome.Random import get_random_bytes, random
from random import randint
from binascii import unhexlify
# NOTE: Just as an example, a random key would be used to test your code
TEST_KEY = "00" * 16
BLOCK_SIZE = 16  # for AES

# ------- Problem 1 Helper functions -------


def hmacsha1(key, message):
    # Note: output is revealed in hex
    return HMAC.new(key, message, SHA1).hexdigest()

# ------- Problem 2 Helper functions -------


def pkcs7_pad(data):
    padding_size = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    if padding_size == 0:
        padding_size = BLOCK_SIZE
    padding = (chr(padding_size)*padding_size).encode()
    return data + padding

def test_q2(q2_cbc_key_reuse, IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
    # Test instance 1
    enc_key = b'\xacc\xea\xad\xe2\x1e\x80>\xe8\xd8\x86#\xe5\x8e\x15]'
    data = b"WordsWordsWords"
    # Create CBC encryption instance and encrypt data (with appropriate padding and IV = 0)
    cipher = AES.new(enc_key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pkcs7_pad(data))

    # Create CBC-MAC instance and build a tag for the plaintext, with the SAME KEY!!!
    tagger = AES.new(enc_key, AES.MODE_CBC, IV)
    correct_tag = tagger.encrypt(pkcs7_pad(data))[-16:]

    # Check whether the provided ciphertext and tag are valid and new
    student_ciphertext = q2_cbc_key_reuse(ciphertext, correct_tag)
    cipher = AES.new(enc_key, AES.MODE_CBC, IV)
    tagger = AES.new(enc_key, AES.MODE_CBC, IV)
    student_plaintext = cipher.decrypt(student_ciphertext) # plaintext corresponding to the new ciphertext
    student_tag = tagger.encrypt(student_plaintext)[-16:] # tag for this new plaintext
    # Check whether the new tag equals the original one, and that the ciphertext is new
    assert(student_tag == correct_tag and student_ciphertext != ciphertext)
    print("Looking good so far")


    # Test instance 2
    enc_key = b'\x8f\x8d,\x15\x14N\xde\xea\x90P\x92\x1b\x1dA\xf0M'
    data = b"TexasHasIslands?"

    # Create CBC encryption instance and encrypt data (with appropriate padding and IV = 0)
    cipher = AES.new(enc_key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pkcs7_pad(data))

    # Create CBC-MAC instance and build a tag for the plaintext, with the SAME KEY!!!
    tagger = AES.new(enc_key, AES.MODE_CBC, IV)
    correct_tag = tagger.encrypt(pkcs7_pad(data))[-16:]

    # Check whether the provided ciphertext and tag are valid and new (same technique as above)
    student_ciphertext = q2_cbc_key_reuse(ciphertext, correct_tag)
    cipher = AES.new(enc_key, AES.MODE_CBC, IV)
    tagger = AES.new(enc_key, AES.MODE_CBC, IV)
    student_plaintext = cipher.decrypt(student_ciphertext)
    student_tag = tagger.encrypt(student_plaintext)[-16:]
    #Tests your chops
    assert(student_tag == correct_tag and student_ciphertext != ciphertext)

    print("Mama we made it!")


def test_q3(q3_harder_cbc_key_reuse):

    # Create random key, plaintext, and IV
    enc_key   = get_random_bytes(16)             # AES-128 key
    enc_iv    = get_random_bytes(16)             # 1 block of IV
    mac_iv    = unhexlify(b'00') * 16            # MAC doesn't have an IV
    plaintext = get_random_bytes(randint(1, 15)) # Less than 1 block of plaintext data

    # Create CBC encryption and MAC instances as before, but with new IV
    cipher = AES.new(enc_key, AES.MODE_CBC, enc_iv)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintext))
    tagger = AES.new(enc_key, AES.MODE_CBC, mac_iv)
    tag = tagger.encrypt(pkcs7_pad(plaintext))[-16:]

    # Check whether the student's (newIV, newCiphertext, newTag) tuple is valid and new

    (newIV, newCiphertext, newTag) = q3_harder_cbc_key_reuse(plaintext, enc_iv, ciphertext, tag)
    cipher = AES.new(enc_key, AES.MODE_CBC, newIV)
    newPlaintext = cipher.decrypt(newCiphertext)
    tagger = AES.new(enc_key, AES.MODE_CBC, mac_iv)
    correct_tag = tagger.encrypt(newPlaintext)[-16:]
    #Tests your chops
    print("correct t =", correct_tag)
    print("new t =", newTag)
    print("old c =", ciphertext)
    print("new c =", newCiphertext)
    assert(newTag == correct_tag and newCiphertext != ciphertext)

    print("Success!")
