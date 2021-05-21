
# This file is provided for you to help with your testing, DON'T submit this file.
# ONLY submit `hw5.py`

# ------- Test functions -------
import hw5_helper
from functools import partial
from binascii import hexlify,unhexlify
from aeskeyexp import aes128_lastroundkey
from hw5 import q1_forge_mac, q2_simple_aes_cache_attack, q3_realistic_aes_cache_attack


def q1_test():
    # case 1
    key1 = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    msg1 = b"Hi There"
    mac1 = "b617318655057264e28bc0b6fb378c8ef146be00"
    assert(mac1 == q1_forge_mac(msg1, partial(hw5_helper.leaky_hmac_verify_example, key=key1)))
    # case 2
    key2 = hexlify(b"Jefe")
    msg2 = b"what do ya want for nothing?"
    mac2 = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    assert(mac2 == q1_forge_mac(msg2, partial(hw5_helper.leaky_hmac_verify_example, key=key2)))
    # case 3
    key3 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    msg3 = unhexlify(b"dd" * 50)
    mac3 = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    assert(mac3 == q1_forge_mac(msg3, partial(hw5_helper.leaky_hmac_verify_example, key=key3)))
    # case 4
    key4 = b"0102030405060708090a0b0c0d0e0f10111213141516171819"
    msg4 = unhexlify(b"cd" * 50)
    mac4 = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
    assert(mac4 == q1_forge_mac(msg4, partial(hw5_helper.leaky_hmac_verify_example, key=key4)))
    # case 5
    key5 = b"0c" * 20
    msg5 = b"Test With Truncation"
    mac5 = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
    assert(mac5 == q1_forge_mac(msg5, partial(hw5_helper.leaky_hmac_verify_example, key=key5)))
    # case 6
    key6 = b"aa" * 80
    msg6 = b"Test Using Larger Than Block-Size Key - Hash Key First"
    mac6 = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    assert(mac6 == q1_forge_mac(msg6, partial(hw5_helper.leaky_hmac_verify_example, key=key6)))
    # case 7
    key7 = b"aa" * 80
    msg7 = b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    mac7 = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    assert(mac7 == q1_forge_mac(msg7, partial(hw5_helper.leaky_hmac_verify_example, key=key7)))
    print("q1 test successful")


def q2_test():
    # case 1
    key1 = b"0123456789abcdef"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key1))==aes128_lastroundkey(key1).hex())
    # case 2
    key2 = b"IjGcug,IR|TYt%%)"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key2))==aes128_lastroundkey(key2).hex())
    # case 3
    key3 = b"0c"*8
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key3))==aes128_lastroundkey(key3).hex())
    # case 4
    key4 = b"5qj7dv1s/lI]~Y%F"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key4))==aes128_lastroundkey(key4).hex())
    # case 5
    key5 = b"Pf(/?.Q`5$rh<a{z"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key5))==aes128_lastroundkey(key5).hex())
    # case 6
    key6 = b"&Tr0.,K7sQ$.rU'%"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key6))==aes128_lastroundkey(key6).hex())
    # case 7
    key7 = b"{S57-Eagt=`H3x3b"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key7))==aes128_lastroundkey(key7).hex())
    # case 8
    key8 = b"568isfuntolearn!"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key8))==aes128_lastroundkey(key8).hex())
    # case 9
    key9 = b"havefundoingwork"
    assert(q2_simple_aes_cache_attack(partial(hw5_helper.leaky_encipher_example, key=key9))==aes128_lastroundkey(key9).hex())
    print("q2 test successful")


def q3_test():
    # case 1
    key1 = b"0123456789abcdef"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key1))==aes128_lastroundkey(key1).hex())
    # case 2
    key2 = b"IjGcug,IR|TYt%%)"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key2))==aes128_lastroundkey(key2).hex())
    # case 3
    key3 = b"0c"*8
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key3))==aes128_lastroundkey(key3).hex())
    # case 4
    key4 = b"5qj7dv1s/lI]~Y%F"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key4))==aes128_lastroundkey(key4).hex())
    # case 5
    key5 = b"Pf(/?.Q`5$rh<a{z"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key5))==aes128_lastroundkey(key5).hex())
    # case 6
    key6 = b"&Tr0.,K7sQ$.rU'%"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key6))==aes128_lastroundkey(key6).hex())
    # case 7
    key7 = b"{S57-Eagt=`H3x3b"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key7))==aes128_lastroundkey(key7).hex())
    # case 8
    key8 = b"MakingHomeworkIs"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key8))==aes128_lastroundkey(key8).hex())
    # case 9
    key9 = b"JustAsHard......"
    assert(q3_realistic_aes_cache_attack(partial(hw5_helper.less_leaky_encipher_example, key=key9))==aes128_lastroundkey(key9).hex())
    print("q3 test successful")

    
# q1_test()
# q2_test()
# q3_test()
