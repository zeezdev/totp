#!/usr/bin/env python

# Google Authenticator (TOTP) implementation in Python
# https://ru.wikipedia.org/wiki/Google_Authenticator

import argparse
import base64
import time
import hashlib
import hmac
import struct


def main(secret):
    secret = secret.replace(' ', '')
    if len(secret) != 32:
        print('The length of the secrect must be 32')
        return

    key = base64.b32decode(secret, True)
    intervals_num = time.time() // 30
    message = struct.pack('>Q', intervals_num)
    hash = hmac.new(key, message, hashlib.sha1).digest()
    offset = ord(hash[19]) & 15
    truncated_offset = hash[offset:offset+4]
    h = (struct.unpack(">I", truncated_offset)[0] & 0x7fffffff) % 1000000
    return h


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--secret', type=str, required=True)

    args = parser.parse_args()
    totp = main(args.secret)
    print(totp)
