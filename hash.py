#!/usr/bin/env python
# coding: utf-8
import bcrypt
import scriptine
import sys
from getpass import getpass

def get_passphrase(confirm=False, length_req=15):
    """Get a passphrase, loop until we get what we want"""
    while True:
        p1 = getpass("Passphrase: ")

        if len(p1) < length_req:
            print "ERROR: Phrase must be longer than %d characters" % length_req
            continue

        if confirm == False:
            break

        p2 = getpass("Repeat: ")
        if p1 == p2:
            break

        print "ERROR: Passphrases no not match"

    return p1

def compare_command():
    """Compare a passphrase to a hash"""
    passphrase = get_passphrase(length_req=-1)
    hashed = raw_input("Hash: ")
    if bcrypt.hashpw(passphrase, hashed) != hashed:
        print 'INVALID'
        sys.exit(1)

    print 'VALID'
    sys.exit(0)

def generate_command(rounds=12):
    """Generate a hash from a passphrase"""
    passphrase = get_passphrase(confirm=True)
    print bcrypt.hashpw(passphrase, bcrypt.gensalt(rounds))

if __name__ == '__main__':
    scriptine.run()
