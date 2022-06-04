# RSA-OAEP Padding + Encryption

import hashlib
from hashlib import sha256
import binascii
import os

key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvVGbCamtmKsmMBgI1AcnfYDawZb0faASx/IYwdxjaQEghH9aKBpF95vgdwBjcr4Szird6ZTi6L+ZmTT+4HkoIhrvNqwca1oI/4g3xzWfTP7bMXaUZ9psR89SFNAdKg/A6WpVFQncgowonQy6UlwFVoCZXLjWAcgIwYa9loqGOhQIDAQAB"
print("\nPublic key: ", key)

m = input("Message: ")
print("\nMessage m: ", m)

random_seed = os.urandom(8)
print("\nrandom seed: ", random_seed)
seed = str(hex(int(binascii.hexlify(random_seed), 16)))[2:] #Random hex of size 8 Bytes #"aa1122fe0815beef" #input("Seed: ")

while(len(seed) != 16): # fixed length of hex number in case it has only 15 nibbles
    seed = "0" + seed
print("\nseed in hex: ", seed)

length = 128 #input("Length of this module in bytes: ")
print("\nlength: ", length)

e = int("10001", 16)
print("\nExponent e: ", e)

n_raw = "00:af:54:66:c2:6a:6b:66:2a:c9:8c:06:02:35:01:c9:df:60:36:b0:65:bd:1f:68:04:b1:fc:86:30:77:18:da:40:48:21:1f:d6:8a:06:91:7d:e6:f8:1d:c0:18:dc:af:84:b3:8a:b7:7a:65:38:ba:2f:e6:66:4d:3f:b8:1e:4a:08:86:bb:cd:ab:07:1a:d6:82:3f:e2:0d:f1:cd:67:d3:3f:b6:cc:5d:a5:19:f6:9b:11:f3:d4:85:34:07:4a:83:f0:3a:5a:95:45:42:77:20:a3:0a:27:43:2e:94:97:01:55:a0:26:57:2e:35:80:72:02:30:61:af:65:a2:a1:8e:85"
n = int(n_raw.replace(":", ""), 16)
print("\nMod n: ", n)


# MGF Functionalities from wikipedia
def i2osp(integer: int, size: int = 4) -> str:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha1) -> str:
    # Mask generation function.
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]

# Input: 
#   String m = message
#   String seed = seed
#   Int length = Number of Bytes in this module
#   int e = Exponent e
#   int n = Mod n
def rsa_oaep(m, seed, length, e, n):
    # lengths
    length_seed = (int((len(seed)/2)))
    length_m = (int(len(m)/2))
    length_datablock = (length - 1) - length_seed
    length_padding = (length_datablock - 1) - length_m

    # padding
    datablock = (length_padding * "00") + "01" + str(m)
    print("\ndatablock: ", datablock)

    # encryption
    msk_for_datablock = binascii.hexlify(mgf1(bytes.fromhex(seed), length_datablock, sha256)).decode('utf-8')
    print("\nMsk for datablock: ", msk_for_datablock)

    msk_datablock = hex(int(datablock, 16) ^ int(msk_for_datablock, 16))
    print("\nMsk data block: ", msk_datablock)

    msk_for_seed = binascii.hexlify(mgf1(bytes.fromhex(str(msk_datablock)[2:]), length_seed, sha256)).decode('utf-8')
    print("\nMsk for seed: ", msk_for_seed)

    msk_seed = hex(int(seed, 16) ^ int(msk_for_seed, 16))
    print("\nMsk seed: ", msk_seed)

    oaep = "00" + str(msk_seed)[2:] + str(msk_datablock)[2:]

    cyphertext = hex(pow(int(oaep, 16), e, n))

    return cyphertext[2:]


print("\n\n\nCyphertext: ", rsa_oaep(m, seed, length, e, n))