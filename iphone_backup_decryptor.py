#!/usr/bin/env python2.7

import Crypto.Cipher.AES
import biplist
import fastpbkdf2
import struct
from termcolor import colored

DICTIONARY = range(1, 999999)


def main():

    manifest = raw_input("Introduce the path to Manifest.plist file: ")
    version = raw_input("Is your iphone version >= 10.2? [Y/N]: ")
    if version == "Y":
        version = True
    elif version == "N":
        version = False
    else:
        print "[!] Wrong answer. Exiting..."
        return

    with open(manifest, 'rb') as infile:
        manifest_plist = biplist.readPlist(infile)

    keybag = Keybag(manifest_plist['BackupKeyBag'])

    for i in DICTIONARY:
        print "Testing for: " + str(i)
        if keybag.unlockWithPasscode(str(i), version):
            print colored("\nKey found: %s\n" % str(i), 'red', attrs=['bold'])
            break


# This section is a modification of some files of
# the iphone-dataprotection project
#
# Mas informacion:
# http://code.google.com/p/iphone-dataprotection/
# https://stackoverflow.com/a/13793043


CLASSKEY_TAGS = ["CLAS", "WRAP", "WPKY", "KTYP", "PBKY"]  # UUID
WRAP_PASSCODE = 2


class Keybag(object):
    def __init__(self, data):
        self.type = None
        self.uuid = None
        self.wrap = None
        self.attrs = {}
        self.classKeys = {}
        self.parseBinaryBlob(data)

    def parseBinaryBlob(self, data):
        currentClassKey = None

        for tag, data in loopTLVBlocks(data):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == "TYPE":
                self.type = data
                if self.type > 3:
                    print "FAIL: keybag type > 3 : %d" % self.type
            elif tag == "UUID" and self.uuid is None:
                self.uuid = data
            elif tag == "WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == "UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey["CLAS"]] = currentClassKey
                currentClassKey = {"UUID": data}
            elif tag in CLASSKEY_TAGS:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey["CLAS"]] = currentClassKey

    def unlockWithPasscode(self, passcode, version):

        if version is True:
            # This step can be avoided in ios < 10.2
            passcode = fastpbkdf2.pbkdf2_hmac('sha256', passcode,
                                              self.attrs["DPSL"],
                                              self.attrs["DPIC"], 32)
        passcode_key = fastpbkdf2.pbkdf2_hmac('sha1', passcode,
                                              self.attrs["SALT"],
                                              self.attrs["ITER"], 32)

        for classkey in self.classKeys.values():
            if not classkey.has_key("WPKY"):
                continue
            k = classkey["WPKY"]
            if classkey["WRAP"] & WRAP_PASSCODE:
                k = AESUnwrap(passcode_key, classkey["WPKY"])
                if not k:
                    return False
                classkey["KEY"] = k
        return True


def loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i + 4]
        length = struct.unpack(">L", blob[i + 4:i + 8])[0]
        data = blob[i + 8:i + 8 + length]
        yield (tag, data)
        i += 8 + length


def unpack64bit(s):
    return struct.unpack(">Q", s)[0]


def pack64bit(s):
    return struct.pack(">Q", s)


def AESUnwrap(kek, wrapped):
    C = []
    for i in xrange(len(wrapped) / 8):
        C.append(unpack64bit(wrapped[i * 8:i * 8 + 8]))
    n = len(C) - 1
    R = [0] * (n + 1)
    A = C[0]

    for i in xrange(1, n + 1):
        R[i] = C[i]

    for j in reversed(xrange(0, 6)):
        for i in reversed(xrange(1, n + 1)):
            todec = pack64bit(A ^ (n * j + i))
            todec += pack64bit(R[i])
            B = Crypto.Cipher.AES.new(kek).decrypt(todec)
            A = unpack64bit(B[:8])
            R[i] = unpack64bit(B[8:])

    if A != 0xa6a6a6a6a6a6a6a6:
        return None
    res = "".join(map(pack64bit, R[1:]))
    return res


if __name__ == '__main__':
    main()
