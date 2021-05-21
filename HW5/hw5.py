#!/usr/bin/env python3
# -*- coding: utf-8 -*-

######################################## HW 5 ########################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below.
The specification of each of the functions is commented out.
"""

import hw5_helper
import os
from Cryptodome.Util.strxor import strxor
from binascii import hexlify,unhexlify
import itertools






rev = ['82',
 '9',
 '106',
 '213',
 '48',
 '54',
 '165',
 '56',
 '191',
 '64',
 '163',
 '158',
 '129',
 '243',
 '215',
 '251',
 '124',
 '227',
 '57',
 '130',
 '155',
 '47',
 '255',
 '135',
 '52',
 '142',
 '67',
 '68',
 '196',
 '222',
 '233',
 '203',
 '84',
 '123',
 '148',
 '50',
 '166',
 '194',
 '35',
 '61',
 '238',
 '76',
 '149',
 '11',
 '66',
 '250',
 '195',
 '78',
 '8',
 '46',
 '161',
 '102',
 '40',
 '217',
 '36',
 '178',
 '118',
 '91',
 '162',
 '73',
 '109',
 '139',
 '209',
 '37',
 '114',
 '248',
 '246',
 '100',
 '134',
 '104',
 '152',
 '22',
 '212',
 '164',
 '92',
 '204',
 '93',
 '101',
 '182',
 '146',
 '108',
 '112',
 '72',
 '80',
 '253',
 '237',
 '185',
 '218',
 '94',
 '21',
 '70',
 '87',
 '167',
 '141',
 '157',
 '132',
 '144',
 '216',
 '171',
 '0',
 '140',
 '188',
 '211',
 '10',
 '247',
 '228',
 '88',
 '5',
 '184',
 '179',
 '69',
 '6',
 '208',
 '44',
 '30',
 '143',
 '202',
 '63',
 '15',
 '2',
 '193',
 '175',
 '189',
 '3',
 '1',
 '19',
 '138',
 '107',
 '58',
 '145',
 '17',
 '65',
 '79',
 '103',
 '220',
 '234',
 '151',
 '242',
 '207',
 '206',
 '240',
 '180',
 '230',
 '115',
 '150',
 '172',
 '116',
 '34',
 '231',
 '173',
 '53',
 '133',
 '226',
 '249',
 '55',
 '232',
 '28',
 '117',
 '223',
 '110',
 '71',
 '241',
 '26',
 '113',
 '29',
 '41',
 '197',
 '137',
 '111',
 '183',
 '98',
 '14',
 '170',
 '24',
 '190',
 '27',
 '252',
 '86',
 '62',
 '75',
 '198',
 '210',
 '121',
 '32',
 '154',
 '219',
 '192',
 '254',
 '120',
 '205',
 '90',
 '244',
 '31',
 '221',
 '168',
 '51',
 '136',
 '7',
 '199',
 '49',
 '177',
 '18',
 '16',
 '89',
 '39',
 '128',
 '236',
 '95',
 '96',
 '81',
 '127',
 '169',
 '25',
 '181',
 '74',
 '13',
 '45',
 '229',
 '122',
 '159',
 '147',
 '201',
 '156',
 '239',
 '160',
 '224',
 '59',
 '77',
 '174',
 '42',
 '245',
 '176',
 '200',
 '235',
 '187',
 '60',
 '131',
 '83',
 '153',
 '97',
 '23',
 '43',
 '4',
 '126',
 '186',
 '119',
 '214',
 '38',
 '225',
 '105',
 '20',
 '99',
 '85',
 '33',
 '12',
 '125']




def q1_forge_mac(message, leaky_hmac_verify=hw5_helper.leaky_hmac_verify_example):
    """Question 1: Timing attack on HMAC's equality test

    In this problem, you will forge an HMAC-SHA1 tag without knowing the key.
    The verification algorithm leaks information about the tag because it
    compares the computed value against the prospective tag one bit at a time.
    
    More specifically:
        Pretend that Alice is sending authenticated messages to Bob
        using a key that they know and **you do not**.
        Bob's code to verify that the messages are properly tagged is 
        given in the 'leaky_hmac_verify' function passed to this function.
        (Please note that the key passed to `leaky_hmac_verify` is
        nondeterministic and unknown to you, Gradescope will test against
        multiple different keys.)

        In summary, Bob's code computes the correct tag
        and compares it to the one that Alice provided. 
        However, Bob's equality comparison test is imperfect:
        if Alice's tag is not correct, then Bob's code reveals (or "leaks")
        the location of the first different bit
        between the correct tag and Alice's invalid attempt. 
        (This leaked bit simulates measuring the time it takes
        for Bob's verification algorithm to run.)

    Your Task:
        Take on the role of Mallory, and find a way to forge an HMAC tag
        on a randomized message without knowing the key.

    Args:
        message (bytes) : the message Alice wants to authenticate
        leaky_hmac_verify (func) : the hmac verify function that Bob would run
            Args:
                message (bytes) : random length bytes message
                claimed_tag (str) : 20 bytes hex-encoded string
                (Note: please ignore argument `key`,
                 you should only pass in 2 inputs)
            (check `hw5_helper.py` for an example `leaky_hmac_verify_example`)

    Output:
        ret (str) : hex-encoded forged HMACSHA1 tag of the given "message"

    Test vector:
        assert(q1_forge_mac(message=b"This message was definitely sent by Alice")
            == hw5_helper.hmacsha1(key=hw5_helper.TEST_KEY, message=b"This message was definitely sent by Alice"))

        Please refer to `hw5_test.py` `q1_test()` for more test cases

    """
    
    working_mac = "00"*20
    i = 0
    verified = leaky_hmac_verify(message, working_mac)
    while verified[0] == False:
        i+=1
        pos = verified[1]
        working_mac_bin = bin(int(working_mac,16))[2:]
        while len(working_mac_bin) < 160:
            working_mac_bin = '0' + working_mac_bin
        flipped = str(abs(int(working_mac_bin[pos])-1))
        working_mac_bin = working_mac_bin[:pos] + flipped + working_mac_bin[pos+1:]
        working_mac = hex(int(working_mac_bin,2))[2:]
        while len(working_mac) < 40:
            working_mac = '0' + working_mac
        verified = leaky_hmac_verify(message, working_mac)
    return working_mac


def q2_simple_aes_cache_attack(leaky_encipher=hw5_helper.leaky_encipher_example):
    """Question 2: Simple cache timing attack on AES

    As Mallory, you must determine the last round key at the very end of AES.
    Since you are a legitimate user on the machine,
    you're welcome to encipher files whenever you'd like,
    and you can also introspect the state of the cache using techniques 
    like Prime+Probe that we discussed in class.

    Bob's code for file enciphering is provided as the 'leaky_encipher'
    routine passed to this function in 'hw5_helper.py'.
    (Please note that the key passed to `leaky_encipher` is
    nondeterministic and unknown to you, Gradescope will test against
    multiple different keys.)
    
    The routine does both of the above operations for you:
    it enciphers the file and then helpfully tells you
    how the 10th round S-box lookups have influenced the state of the cache,
    so you don't need to inspect it yourself. Hence, 'leaky_encipher' has two
    outputs: the actual ciphertext plus a Python set stating which bytes
    in cachelines are accessed during the final round's SubBytes operation. 

    Recall that SubBytes works on a byte-by-byte basis: each byte of the state
    is used to fetch a specific location within the S-box array.
    The 'leaky_encipher' routine tells you which elements of 
    the S-box array were accessed, which as you recall from Lecture 8
    is correlated with the key. 

    Two caveats:
        -   This problem conducts a last-round attack: that is,
            our attack scenario is explained in lecture 8 slide 10
            As a result, the cache lines are correlated with the
            last round key of AES, and not the first round key. 
            This is acceptable to Mallory because there's a known,
            public permutation that relates all of the round keys.

            In fact in helper file 'aeskeyexp.py', we have provided a routine
            'aes128_lastroundkey' that converts first -> last round keys. 
            We didn't actually give you the converse, but we assure you that
            it's equally as easy to compute. Let's just declare victory
            as Mallory if we can find the last round key.

        -   Mallory cannot interrupt the state of execution of AES.
            She can only observe the contents of the cache after 
            it is finished. As a result: `leaky_encipher` only tells you
            the **set** of all table lookups made to the 10th 
            round S-box across all 16 bytes, without telling you
            which lookup is associated with which byte.

    Your Task:
        Complete this function with a solution that calls 'leaky_encipher'
        as many times as you wish and uses the results to determine the key.
        
    Args:
        leaky_encipher (func) : performs an AES encipher on a 16-bytes input 
            Args:
                file_bytes (bytes) : 16-bytes input to be passed to AES
                                     for enciphering
                (Note: please ignore argument `key`,
                 you should only pass in 1 input)
            Output:
                ret (str, set) : a list with the actual ciphertext and
                                 a Python set stating which bytes are accessed
                                 during the final round's SubBytes operation.
            (check `hw5_helper.py` for an example `leaky_encipher_example`)
                                 
    Output:
        ret (str) : hex-encoded 16-bytes string that represents
                    the lastroundkey of AES in leaky_encipher
    Test Vector:
        assert(q2_simple_aes_cache_attack()
            == hw5_helper.aes128_lastroundkey(hw5_helper.TEST_KEY).hex())
            
        Please refer to `hw5_test.py` `q2_test()` for more test cases

    Note:
        The file `hw5_helper.py` contains some helper functions that
        you will find useful in solving this question.
        
    hex is 37 98 53 13   
    """
    round = 0
    result_zeros = leaky_encipher(b'0'*16)
    while round < 5:
        current_pos = 0
        hits = []
        possibilities = [0]*16
        for val in result_zeros[1]:
            lookup = rev.index(str(val))
            hits.append(bytes(hex(lookup)[2:].encode()))
        while current_pos < 16:
            cipher_byte = hexlify(result_zeros[0][current_pos:current_pos+1])
            possibilities[current_pos]=options(cipher_byte, hits)
            current_pos += 1
        round += 1
        if round == 1:
            first_pos = possibilities
            result_zeros = leaky_encipher(b'1'*16)
        if round == 2:
            second_pos = possibilities
            result_zeros = leaky_encipher(b'01'*8)
        if round == 3:
            third_pos = possibilities
            result_zeros = leaky_encipher(b'10'*8)
        if round == 4:
            fourth_pos = possibilities
            result_zeros = leaky_encipher(b'1001'*4)
    key = b''
    for slot in range(len(possibilities)):
        for value in possibilities[slot]:
            if value in first_pos[slot] and value in second_pos[slot] and value in third_pos[slot] and value in fourth_pos[slot]:
                key += hexlify(value)
    return key.decode('ascii')
        
    
    


def options(ciphertext, hits):
    all_poss = []
    for outcome in hits:
        if len(outcome) == 1:
            outcome = b'0' + outcome
        xored_val = strxor(unhexlify(outcome), unhexlify(ciphertext))
        all_poss.append(xored_val)
    return all_poss




def q3_realistic_aes_cache_attack(less_leaky_encipher=hw5_helper.less_leaky_encipher_example):
    """Question 3: Realistic cache timing attack on AES

    In this problem, you're still acting as Mallory and
    trying to perform a cache timing attack. 
    There's just one new hurdle that you must overcome.
    (As a consequence: do not attempt to solve 
    this problem until you have already solved Question 2.)

    We made one unrealistic assumption in the 'leaky_encipher' routine:
    We provided you with the set of bytes that were accessed in the final
    round of AES. Real caches unfortunately do not provide byte-level
    accuracy. I'll spare you the details; the upshot is that it is common
    for 16 values of the SubBytes array to fit within a single cacheline.

    That is: suppose Bob weren't running AES at all, but instead only makes
    a single table lookup S[x] into the SubBytes array S.
    By observing which portion of the cache is activated, 
    a cache attack would let Mallory know whether Bob's access x was
    in the range 0-15, or the range 16-31, ... or the range 240-255.
    However, Mallory couldn't tell anything beyond that. 
    In other words: Mallory can learn the upper 4 bits of x
    but not the lower 4 bits.

    The 'hw5_helper.py' file contains Bob's code for this problem.
    It is the routine `less_leaky_encipher_example`
    that only provides cachelines (the set of the upper 4 bits
    of the location of each table lookup) to Mallory; it otherwise 
    runs similarly to the code in Question 2.
    (Please note that the key passed to `less_leaky_encipher` is
    nondeterministic and unknown to you, Gradescope will test against
    multiple different keys.)

    Your Task:
        Perform a cache timing attack even in this restricted setting.
        Your input-output behavior should be the same as stated in Question 2.
        (The solution to this problem is pretty much exactly what
        Osvik, Shamir, and Tromer did to break Linux's full disk encryption
        software, called dmcrypt.)

    Args:
        less_leaky_encipher (func) : performs an AES encipher on 16-bytes  
            Args:
                file_bytes (bytes) : 16-bytes input to be passed to AES
                                     for enciphering
                (Note: please ignore argument `key`,
                 you should only pass in 1 input)
            Output:
                ret (str, set) : a list with the actual ciphertext and
                                 a Python set stating which cachelines are
                                 accessed during the final round's SubBytes
                                 operation.
            (check `hw5_helper.py` for an example `less_leaky_encipher_example`)
                                 
    Output:
        ret (str) : hex-encoded 16-bytes string that represents
                    the lastroundkey of AES in `less_leaky_encipher`
    Test Vector:
        assert(q3_realistic_aes_cache_attack()
            == hw5_helper.aes128_lastroundkey(hw5_helper.TEST_KEY).hex())

        Please refer to `hw5_test.py` `q3_test()` for more test cases

    """
    
    result_zeros = less_leaky_encipher(b'0'*16)
    round_num = 1
    all_poss = []
    key = b''
    while round_num <= 50:
        hits  = set()
        possibilities = []
        for i in result_zeros[1]:
            for j in range(16):
                poss = rev.index(str(16*i+j))
                hits.add(bytes(hex(poss)[2:].encode()))
        for byte in range(len(result_zeros[0])):
            possibilities.append(options(hexlify(result_zeros[0][byte:byte+1]), hits))
        

        result_zeros = less_leaky_encipher((bytes(str(round_num).encode())*16)[:16])
        round_num += 1
        all_poss.append(possibilities)
#    print(b'7' in all_poss[55][0])
    for slot in range(len(possibilities)):
        false = []
        for value in possibilities[slot]:
            for count in range(len(all_poss)):
                if value not in all_poss[count][slot]:
                    false.append(value)
        for value in possibilities[slot]:
            if value not in false:
                key += hexlify(value)
    return key.decode('ascii')

#        possibilities.append(options(i))
    # hits now contains all of the values that were queried to the Sbox