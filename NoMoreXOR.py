#!/usr/bin/env python

# NoMoreXOR.py was created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
#		@hiddenillusion
# Version 0.0.2
# Date: 12-11-2012
# To-Do:
#	- add YARA scanning to try and detect ROR/ROL
#	- add ability to ROL/ROR then XOR
#	- process other size xor? (i.e. single byte)
#	- add ability to skip certain bytes (i.e. \x00)
import os
import re
import sys
import argparse
import binascii
import collections
from itertools import izip, cycle
try:
    import yara
except ImportError:
    print "[!] Yara module not installed"
    sys.exit()	

# Formatting jargon
def header(msg):
    return msg + "\n" + ("=" * 45)

def notes():
    return "\tOccurences | Character(s)" + "\n" + ("-" * 45)

# What did you give me to do?
parser = argparse.ArgumentParser(description='Tool to help guess a files 256 byte XOR key by using frequency analysis.')
parser.add_argument('-a', '--analyze', action='store_true', help='Auto analyze the specified file by looking for all possible XOR keys then apply each of them & scan with YARA to try and determine if it\'s the correct XOR key (requires an output file)', required=False)
parser.add_argument('-c', '--convert', action='store_true', help='Convert the input file to a hex_file (requires an output file)', required=False)
parser.add_argument('-xor', nargs=1, metavar='key', help='XOR the file with the supplied XOR key (requires an output file)', required=False)
parser.add_argument('-g', '--guess', action='store_true', help='Print out information from the hex_file including most common characters and possible SHA256 keys', required=False)
parser.add_argument('-o', '--out', metavar='outfile', help='Name of output file to create', required=False)
parser.add_argument('-y','--yararules', help='Path to YARA rules to be used during auto analysis if different than what\'s hardcoded', required=False)
parser.add_argument('Path', help='Path to file to be analyzed')
args = vars(parser.parse_args())

# Set the path to file(s)
filename = args['Path']

# output file is required for: analyze,convert,xor
if not args['out']:
    if args['analyze'] or args['convert'] or args['xor']:
        print "[!] An output file is required for this task"
        sys.exit()
else: 
    new_file = args['out']

# Static xor key to use
if args['xor']:
    key = args['xor'][0]

# YARA rules provided?
if not args['yararules']:
    rules = '/path/to/rules.yara'
else:
   rules = args['yararules']

# Placeholders
keys = []

# Configure YARA rules
def yarascan(filename):
    print "[+] Scanning with Yara"
    print "[-] Using rules" + ('.'*28 + ': ') + rules
    if not os.path.exists(rules):
            print "[!] Correct path to YARA rules?"
            sys.exit()
    try:
        r = yara.compile(rules)
        ymatch = r.match(filename)
        if len(ymatch):
            print "[+] YARA hit(s):",ymatch
            print "[+] Possible XOR key:",key
            print "[+] Un-XOR'ed file should be examined:",unxored
            print "[+] Stopping processing"
            sys.exit()
    except Exception, msg:
        print "[!] YARA compile error: %s" % msg
        sys.exit()

# HEX it up?
def hexMeBro(filename):
    print "[+] HEXing" + ('.'*32 + ': ') + filename
    with open(filename, 'rb') as f:
        content = f.read()
        print "[+] Saving as" + ('.'*29 + ': ') + new_file
        with open(new_file, 'w') as nf:
            nf.write(binascii.hexlify(content))

# Attempt to guess the XOR key with frequency analysis
def guess(filename):
    print "[+] Attempting to guess the XOR key of....:",filename
    with open(filename, 'r') as f:
        content = f.read()

    def charCounter():
        lst = char_2.most_common(5)
        return '\n'.join("\t%10s = 0x%s" % (occur,chars) for chars,occur in lst)

    def five_twelver():
        ret = []
        for i in char_mucho.most_common(5):
            if not re.match(r'(.)\1{2,}', i[0]) and not re.match(r'(..)\1{2,}', i[0]):
                ret.append(i)
                keys.append(i)
        return '\n'.join("\t%s = %s\n" % (occur,chars) for chars,occur in ret)

    """
    Section to look for SHA256 key
    """
    # Set up some place holders for data
    cnt_2 = []
    cnt_mucho = []
    length = len(content)

    # since file is one big hex blog, read 2 chars at a time
    two_step = [content[i:i+2] for i in range(0, len(content), 2)]
    for combo in two_step:
        cnt_2.append(combo)

    big_daddy = [content[i:i+512] for i in range(0, len(content), 512)]
    for combo in big_daddy:
        cnt_mucho.append(combo)

    # get your count on
    char_2 = collections.Counter(cnt_2)
    char_mucho = collections.Counter(cnt_mucho)

    """
    Return the results and make it look purdy...
    """
    results = []
    results.append("[+] Size of content.......................: %d" % length)
    results.append("[+] Total pages (1024k)...................: %d" % (length / int(1024)))
    results.append("[+] Total contiguous 512 chunks...........: %d" % (length / int(512)))
    results.append(header("[+] Top (5) overall chars"))
    results.append(notes())
    results.append(charCounter())
    results.append("")
    results.append("[+] Total number of unique 512 chunks.....: %s" % len(char_mucho))
    results.append(header("[+] Top (5) 512 char sequences after cleanup"))
    results.append(notes())
    results.append(five_twelver())
    print '\n'.join(results)

# XOR that baby
def hex2str(h):
    """
    Taking 2 bytes at a time from the hex key and converting
    to an integer then taking their char representation and
    re-building out key.

    Idea sourced from : http://www.malwaretracker.com/tools/cryptam_unxor_php.txt
    """
    bytes = []
    hlen = len(h)
    for i in range(0, hlen, 2):
        bytes.append(chr(int(h[i:i+2], 16)))
    return ''.join(bytes)

def xor(content, key):
    """
    I know there're other methods to do the same thing
    and they're probably faster too, but this works for now
    """
    print "[+] XOR'ing" + ('.'*32 + ': ') + filename
    dlen = len(content)
    klen = len(key)
    decoded = ''
    i = 0
    while i < dlen:
        idx = i % klen
        newbie = ''
        newbie = ord(content[i]) ^ ord(key[idx])
        decoded += chr(newbie)
        i += 1
    return decoded
    
# what to do... what to do...
if args['convert']:
    hexMeBro(filename)
elif args['guess']:
    guess(filename) 
elif args['xor']:
    print "[+] key used : %s" % key
    with open(filename, 'r') as f:
        content = f.read()
    """
    For now I'm just XOR'ing the entire file
    """
    with open(new_file, 'wb') as nf:
        nf.write(xor(content, hex2str(key)))
    print "[+] Saving as: %s" % new_file
elif args['analyze']:
    print "[+] Attempting auto analysis" 
    #1 - open file in hexMeBro(), hex it and saves as new_file
    hexMeBro(filename)
    #2 - send new_file 'hex_file' to guess()
    guess(new_file)
    #3 - for each possible key found, try that key against the original file 'filename'
    i = 0
    for key,occur in keys:
        unxored = filename + '.' + str(i) + '.' + 'unxored'
        #4 - xor original file 'filename' with key
        print "[+] Trying XOR key :",key
        #4 - xor original file 'filename' with key
        with open(filename, 'r') as f:
            content = f.read()
        with open(unxored, 'wb') as nf:
            nf.write(xor(content, hex2str(key)))
        print "[+] Saving as" + ('.'*30 + ': ') + unxored
        #5 - yarascan newly saved file.(xored number).unxored
        yarascan(unxored)
        i += 1
