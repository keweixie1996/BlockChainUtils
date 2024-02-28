# -*- coding:utf-8 -*-

import hashlib
import cbor2


def str2hexstr(s):
    s_bytes = s.encode("utf-8")
    s_hex = s_bytes.hex()
    return s_hex

def hexstr2str(s_hex):

    s_bytes = bytes.fromhex(s_hex)
    s = s_bytes.decode("utf-8")
    return s


def cbor_encode(obj):
    s_bytes = cbor2.dumps(obj)
    s_hex = s_bytes.hex()
    return s_hex

def cbor_decode(s_cbor_hex):
    s_bytes = bytes.fromhex(s_cbor_hex)
    obj = cbor2.loads(s_bytes)
    return obj


def str2md5(s):
    s_bytes = s.encode("utf-8")
    md5 = hashlib.new("md5", s_bytes).hexdigest()
    return md5


def test():

    a = "7b636b6272632d32302c6d696e742c636b4f5244492c313030307d"
    print(hexstr2str(a))


if __name__ == "__main__":
    test()

