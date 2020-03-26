#!/usr/bin/python

import sys
import os
import string

import binascii as ba
import struct

DEBUG = False

try:
	file= open(sys.argv[1], "rb")
except:
	print 
	print '\tusage: mifarecrack.py <proxmark3 logfile>'
	print
	sys.exit(True)


trace_size = os.path.getsize(sys.argv[1])
complete_auth_found = False
while file.tell()<= trace_size:
    auth_code = file.read(2)
    if not auth_code:
        break
    if auth_code == b'\x93\x70':
        #auth found.
        uid = "0x"+ba.b2a_hex(file.read(4))
        if(DEBUG):print("addr: %x uid: %s" % ( file.tell(),uid))
        
        #jump over select id
        file.read(25)
        use_key = file.read(1)
        #print(use_key)
        if use_key == b'\x60' or use_key == b'\x61':
            block = struct.unpack("b",file.read(1))[0]
            if use_key == b'\x60':key_type = "A" 
            if use_key == b'\x61':key_type = "B" 
            
           
            file.read(11)
           
            tag_challenge = "0x"+ba.b2a_hex(file.read(4))

            file.read(9)
            reader_challenge = "0x"+ba.b2a_hex(file.read(4))
            reader_response = "0x"+ba.b2a_hex(file.read(4))
            file.read(7)
            tag_response_size = struct.unpack("b",file.read(1))[0]
            if(DEBUG):print("tag_response_size %d" % ( tag_response_size))
            file.read(1)
            tag_response = "0x"+ba.b2a_hex(file.read(4))
            
            if tag_response_size!=4 or tag_response == "0x500057cd":
                if(DEBUG):print("Failed Auth found.")
                if(DEBUG):print("Block: %d with key:%s" % (block, key_type))
                continue
            print("Section:%d  Block: %d with key:%s" % (block/4,block, key_type))
            if(DEBUG):print("tag_challenge = "+ tag_challenge)
            if(DEBUG):print("reader_challenge = "+ reader_challenge)
            if(DEBUG):print("reader_response = "+ reader_response)
            if(DEBUG):print("tag_response = "+ tag_response)
            crackstring= './mifarecrack '+ uid

            # now process challenge/response
            crackstring += ' ' + tag_challenge
            crackstring += ' ' + reader_challenge
            crackstring += ' ' + reader_response
            crackstring += ' ' + tag_response
            print 'Executing ', crackstring
            complete_auth_found = True
            os.system(crackstring)

        else:
           continue
        
if not complete_auth_found:
    print("No complete auth found!!!")

