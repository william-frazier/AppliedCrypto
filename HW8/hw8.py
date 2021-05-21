#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##################################### HW8 #####################################

"""
List you collaborators here:
                                party one 
                                party two...
Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import hw8_helper
from Cryptodome.PublicKey import RSA
from math import gcd, floor, sqrt
from Cryptodome.Util.number import inverse


def q1_break_poor_rsa(rsa_keys):
    """Question 1 : Breaking RSA keys with poor randomness
    The RSA public key encryption and digital signature schemes (named after 
    its creators Rivest, Shamir, and Adleman) essentially relies upon the 
    hardness of factoring.
    An RSA private key consists of two prime numbers `p` and `q`, and the 
    corresponding public key equals the product of the two primes `N = p * q`.
    
    The RSA scheme relies upon good sources of randomness when generating the 
    private key: if your entropy source isn't strong, and several people on the 
    Internet choose the same `p` **or** the same `q`, then the scheme will
    break. And by this point in the class I think you can see where
    I'm going with this. Unfortunately, this kind of poor random key generation
    is exactly what has happened with many computers on the Internet,
    as shown by https://ia.cr/2012/064 and several subsequent papers.
    
    Your Task:
        
        Given the list of RSA keys in `rsa_keys`, crack as many of the RSA keys 
        as you can. Do **not** try a brute force attack to factor the public 
        keys (that's the next problem), but instead use the fact that factors 
        might be repeated between keys.
    
    Args:
    
        One of the common ways public/private RSA keys are stored and
        transmitted is by using one of the X509 File Extensions
        (`.CRT`, `.PEM`, ...). In this homework, we'll use the
        `.PEM` extension to handle the public keys.
        For example, given the public key file `pub_key.pem`,
        you can use Python as follows to decode the key:
        ```
            from Cryptodome.PublicKey import RSA
            pem1 = open("pub_key.pem", 'r').read()
            k1 = RSA.importKey(pem1)
        ```
        In this problem, your input `rsa_keys` will be a list of strings that
        represents RSA keys in PEM encoding. For example, to decode the first 
        RSA key in the input list, you can do the following:   
        
        `k1 = RSA.importKey(rsa_keys[0])`
        
    Output:
    
        ret (list(Cryptodome.PublicKey.RSA.RsaKey)): A list containing all the
                        private keys of the cracked RSA keys.
    
    Note:
    
        - The number of bad RSA keys is not always equal to the number of given
            keys, so don't assume any fixed number.
        
        - Given an `n`, `e` and `d` (private exponent), you can create an 
            instance of the `Cryptodome.PublicKey.RSA.RsaKey` object as follows:
            ```
            from Cryptodome.PublicKey import RSA
            n = 133
            e = 5
            d = 65
            priv_key = RSA.construct((n, e, d), False)  # False is passed to 
                                                        # disable parameter
                                                        # checks
            ```
        - Feel free to use the helper functions in `hw8_helper.py`, like
            `egcd` and `mod_inv`
            or the imported library functions at the header of this file
            
    Test Vector:
        This problem is inspired from the challenge here: 
            http://www.loyalty.org/~schoen/rsa/
        So one way you can verify your solution is to use the keys provided
        in the challenge. I have already imported the keys in
        `hw8_helper.q1_testkeys`.
        So you can check your implementation as follows:
        ```
        assert(hw8_helper.q1_test(q1_break_poor_rsa(hw8_helper.q1_testkeys)))
        ```
    """

    i = 0
    pairs = []
    broken_keys = []
    for i in range(len(rsa_keys)):
        k1 = RSA.import_key(rsa_keys[i])
        j = i + 1
        while j < len(rsa_keys):
            k2 = RSA.import_key(rsa_keys[j])
            gcd_val = hw8_helper.egcd(k1.n,k2.n)[0]
            if gcd_val != 1:
                pairs.append([k1.n, k1.e, gcd_val])
                pairs.append([k2.n, k2.e, gcd_val])
            j += 1
    for key in pairs:
        broken_key_n = key[0]
        broken_key_e = key[1]
        broken_key_p = key[2]
        broken_key_q = broken_key_n//broken_key_p
        broken_key_mod = (broken_key_p-1) * (broken_key_q-1)
        broken_key_d = inverse(broken_key_e, int(broken_key_mod))
        broken_keys.append(RSA.construct((broken_key_n, broken_key_e, broken_key_d), False))
    return broken_keys
    


def q2_break_small_rsa(rsa_key):
    """Question 2: Breaking small RSA keys
    Humans have been trying to figure out how to factor integers for at least 
    2000 years. While we're still not great at it, we are decently good... 
    at least compared to the elliptic curve Diffie-Hellman problem. As a result, 
    RSA keys used in cryptography are quite large: they involve numbers that 
    are 1500-4000 bits long.
    
    Sometimes though, bad programmers just make your life easier. If you don't
    believe me, read this stream of Twitter posts about the weak RSA keys used
    to control medical devices that are implanted in people's hearts: 
            https://twitter.com/matthew_d_green/status/818816372637650948
    
    Your Task:
    
        Break an RSA public key whose factors are small enough to find rather 
        quickly on a modern computer. For this problem, you can assume that
        the modulus `n` is no longer than (2^{33} - 1), so 33 bits long.
        
        You may **not** use any library provided code to solve this problem.
        I claim that even the simplest approach to solve this problem will
        be sufficient given the small RSA modulus length, so there's no need
        to call anybody else's code. (Exceptions: you may call the
        RSA.importKey routine listed in Question 1 to parse the key, and
        you may use the hw8_helper file.)
        
    Args:
    
        rsa_key     (str):  A string with a similar format to the items
                            of the list `rsa_keys` from the previous question
                            (`.PEM` encoding)
    
    Output:
    
        ret (Cryptodome.PublicKey.RSA.RsaKey): the Private RSA key used to 
                                    generate the input public RSA key. 
    
    Test Vector:
        This problem is inspired from the challenge here: 
            https://id0-rsa.pub/problem/09/
        So feel free to use the submission box on the web page to verify your
        solution, or at least test against the provided test vector on the page.
        ```
        assert(hw8_helper.q2_test(q2_break_small_rsa(hw8_helper.q2_testkeys)))
        ```
    """
    k1 = RSA.import_key(rsa_key)
    print(k1.n)
    for i in range(3,k1.n,2):
        print(i)
        if hw8_helper.egcd(i,k1.n)[0] != 1 and i != 0:
            q = k1.n // i
            mod_val = (q-1)*(i-1)
            d = hw8_helper.mod_inv(k1.e, mod_val)
            return RSA.construct((k1.n, k1.e, d), False)
