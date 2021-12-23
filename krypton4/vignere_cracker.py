#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ngram_score as ns
import sys
import numpy as np
import re
#import random
#from itertools import combinations
#from nltk.corpus import words

keylength = sys.argv[2]


#Ditch special characters & spaces, convert to all uppercase string
def sanitize_str(ciphertext_str): 
    return(re.sub(r"[^a-zA-Z]", "", ciphertext_str).upper())

#string to num list:
def s_to_num_l(string):
    """
    nums = [i for i in range(26)]
    lets = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    s_to_n_d = dict(zip(lets, nums)) 
    """
    s_to_n_d = {'A': 0,
     'B': 1,
     'C': 2,
     'D': 3,
     'E': 4,
     'F': 5,
     'G': 6,
     'H': 7,
     'I': 8,
     'J': 9,
     'K': 10,
     'L': 11,
     'M': 12,
     'N': 13,
     'O': 14,
     'P': 15,
     'Q': 16,
     'R': 17,
     'S': 18,
     'T': 19,
     'U': 20,
     'V': 21,
     'W': 22,
     'X': 23,
     'Y': 24,
     'Z': 25}
    return( [s_to_n_d[k] for k in string])

# number list to string           
def num_l_to_st(num_l):
    """
    nums = [i for i in range(26)]
    lets = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    n_l_to_st_d = dict(zip(nums, lets)) 
    """
    n_l_to_st_d = {0: 'A',
     1: 'B',
     2: 'C',
     3: 'D',
     4: 'E',
     5: 'F',
     6: 'G',
     7: 'H',
     8: 'I',
     9: 'J',
     10: 'K',
     11: 'L',
     12: 'M',
     13: 'N',
     14: 'O',
     15: 'P',
     16: 'Q',
     17: 'R',
     18: 'S',
     19: 'T',
     20: 'U',
     21: 'V',
     22: 'W',
     23: 'X',
     24: 'Y',
     25: 'Z'}
    ret_str = ""
    ret_str = ret_str.join([n_l_to_st_d[k] for k in num_l])
    return(ret_str)
    
def encrypt_vignere(plaintext_s, key_s):
    
    ptnum_l = s_to_num_l(plaintext_s)
    keynum_l = s_to_num_l(key_s)
    
    enc_l = [ (ptnum_l[i] + keynum_l[i % len(keynum_l)])%26  for i in range(len(ptnum_l))]
    return(num_l_to_st(enc_l))    
    
def decrypt_vignere(ciphertext_s, key_s):
    
    ctnum_l = s_to_num_l(ciphertext_s)
    keynum_l = s_to_num_l(key_s)
  
    dec_l =[ (ctnum_l[i] - keynum_l[i % len(keynum_l)])%26  for i in range(len(ctnum_l))]
    return(num_l_to_st(dec_l))

def L(ciphertext_str, ngram_l):
    
    score_l = []
    coeff_l = []
    for [ngram_obj, c] in ngram_l:
        
        score_l.append( ngram_obj.score(ciphertext_str) )
        coeff_l.append(c)
    # Return weighted sum:
    return( np.dot(score_l, coeff_l))

def good_guess(ciphertext_s, ngram_l):
    print("Getting initial guess from single letter freq. analysis:")
    best_key_s = "AAAAAA"
    best = L( decrypt_vignere(ciphertext_s, best_key_s), ngram_l[0:1] )
    print("Initial guess: ", best_key_s, " Initial Score: ", best)
    
    testkey_s = best_key_s
    ct_len = len(ciphertext_s)
    
    for i, c in enumerate(best_key_s):
        print("Optimizing i = ", i, "/", len(best_key_s))
        
        ct_s = [ciphertext_s[k] for k in range(ct_len) if (k % 6 == i ) ]
        best = L ( decrypt_vignere(ct_s, c) , ngram_l[0:1])
        for let in "ABCDEFGHIJKLMNOPQRSTUVWXYZ": 
            scr = L( decrypt_vignere(ct_s, let), ngram_l[0:1] )
            if scr > best: 
                best = scr
                best_key_s = best_key_s[0:i] + let + best_key_s[i+1:]
                print(i,best_key_s, best)
    print("Initial Guess Complete:", best_key_s)  
    return(best_key_s)

def bigram_guess(ciphertext_s, ngram_l):
    print("Guessing key in 2 letter chunks by bigram analysis:")
    best_key_s = "AAAAAA"
    best = L( decrypt_vignere(ciphertext_s, best_key_s), ngram_l[1:2] )
    print("Initial guess: ", best_key_s, " Initial Score: ", best)
    
    testkey_s = best_key_s
    ct_len = len(ciphertext_s)
    
    for i in [n for n in range(len(best_key_s)) if (n % 2 == 0)]:
        
        print("Optimizing positions i = ", i, i+1, " of key")
        
        ct_s = [ciphertext_s[k] for k in range(ct_len) if (k % 6 == i or k%6==i+1) ]
        best = L ( decrypt_vignere(ct_s, best_key_s[i:i+2]) , ngram_l[1:2])
        
        for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ": 
            for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                scr = L( decrypt_vignere(ct_s, a+b), ngram_l[1:2] )
                if scr > best: 
                    best = scr
                    best_key_s = best_key_s[0:i] + a + b + best_key_s[i+2:]
                    print(i,best_key_s, best)
    print("Bigram Guess Complete:", best_key_s)  
    return(best_key_s)

def make_pretty(string):
    return(" ".join([string[i:i+6] for i in range(len(string)) if (i%6 == 0)]))

#Read in and sanitize ciphertext from commandline argument 
ct_file = open(sys.argv[1])
ciphertext_s = sanitize_str( ct_file.read() ) 

#Instantiating ngram classes is costly so doing it only once. Used in L()
f_1 = ns.ngram_score('english_monograms.txt')
f_2 = ns.ngram_score('english_bigrams.txt')
f_3 = ns.ngram_score('english_trigrams.txt')
f_4 = ns.ngram_score('english_quadgrams.txt')
ngram_l = [ [f_1, 2.0], [f_2,1.5], [f_3,1.4], [f_4,1.0] ]

key_s = good_guess(ciphertext_s, ngram_l)
print( make_pretty( decrypt_vignere(ciphertext_s, key_s) ) )

key_s = bigram_guess(ciphertext_s, ngram_l)
print( make_pretty( decrypt_vignere(ciphertext_s, key_s) ))

"""
best_key_s = key_s
best = L( decrypt_vignere(ciphertext_s, best_key_s),ngram_l )
for i, c in enumerate(best_key_s):
    for j in range(26):
        testkey_s = best_key_s
        
        testkey_s = testkey_s[0:i] + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[j] + testkey_s[i+1:]
        scr = L ( decrypt_vignere(ciphertext_s, testkey_s), ngram_l )
        
        if scr > best:
            best = scr
            best_key_s = testkey_s
            print(best_key_s, best) 

print( make_pretty(decrypt_vignere(ciphertext_s, best_key_s)) )

words_list = words.words()
keys_l = [k for k in words_list if (len(k)==6) ]
#random.shuffle(keys_l)

ct_file = open(sys.argv[1])
ciphertext_s = sanitize_str( ct_file.read() ) 

best_key = "AAAAAA"
best = L( decrypt_vignere(ciphertext_s, best_key), ngram_l)

len_keys = len(keys_l)
for i, key in enumerate(keys_l):
    key_s = sanitize_str(key)
    scr = L(  decrypt_vignere(ciphertext_s, key_s) , ngram_l)
    if scr > best:
        best = scr
        best_key = key_s
        print(i,"/", len_keys, best_key, best)
"""


