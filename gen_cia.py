#!/usr/bin/env python3

import base64
import binascii
import glob
import itertools
import math
import os
import struct
import sys
import zlib
from Crypto.Cipher import AES

if not os.path.isfile("decTitleKeys.bin"):
    sys.exit("decTitleKeys.bin not found.")

readsize = 8 * 1024 * 1024

# certificate chain. every CIA shares the same one or it can't be installed.
certificate_chain = zlib.decompress(base64.b64decode(b"""
eJytkvk/E44fx9GsT58ZsrlvaUmxMJ8RQiTXx50wRRbmWObKkTnTZ5FQxsxNJlfKyvGNCpnJbY7k
+Nacc205P+X69H30+Qv0fb5/fr0er8f78eTi5jqCM9Riv24u8iXhx7jVsVIZzqaWhOJ7kuklQk6R
8/xbJ6Lb+QXVJ7QnF8iZTxecR31JlPlpX759zbNPH/PGIw4S9Lt0jsTJFIDfjZXCYy+9rP1mKOld
KmX8iv1g/s7IsF/ZVURRInZu6M0Io/hiBz1CEqGAvO4aRn57FH6byC7cRnUlhBe08evPdCc8kgs3
QN8369giOLrdzAkZ0UtxOqj+dFWG6HDRDyK2a3I/YYhe6pEMrNu9ZhMFmS9KarGVqRtRLTVOTbCB
Xi6voS63punmDcMfKXdWjbOdaDxipmO35P5SZwyMjS0ag9M9pCKzxwlG7bmyqmfxOVfxtmdFsAHR
EtXmYeZI4+jwfTn5L+bEAaFCTHWh+Aa6o9QxseI1htCoeDNhIDk3NuCymZiGaDzC3CJRTcMCdk4d
PTa4ZG3RmMlDtdt6ZmBCI1+Pfmguxs55Vzw1AhE0xAntxVu2iPTVv2/ZXg4MKwox6ZrKXF/5mNrD
CwcRki7t1ZxBQxw2wCKz33PPWn0izZMGrrubTNij14/5nXWPzEsZRgnzUKrwuvSP7aHZD/ERPoJ0
wHviCZurLJkeGLKz5a6tbZUfGZD27AJtI8ygcBxUgj3q7Ng7r2lVwnqyFgSCXeHDaxspNvHVs9Tw
SfdubMinHwg+j3fs1R9EhVy3zUjz+/NGl6Uq1y9gFxAQ8iv5H3AbGZ77icbhCu4ssP1rIzqZq1/k
aYsb1lvaf6ceTbYIWykguj/XjI97xX+lMui4cFEYTjfy3P55FlvKvUk6y+R27XlMN+AFyQ7Vifkq
zRy3mRmb5wTOenxiHlPQYDHQW9KjLQXrT8plUj3thwIn79xt/NrQG6zJ2XTgRRctNmijP+ewuLll
sx3QN5RwcqxucKVpDBTsBStKwJ46LiuHmbocBE237fOhSVL4v42ZFW7LOmSvMciDD3C8iPjH79UO
mjW2mijgDvHrxU3tWDlQDRbYn2s4nsLqkBO2fJJwxufdA58enaPnudDucBMVjdgbpYv+6a7DHpoR
bUs3e43ZTljofyoICO6cC0urjAgu7h93qO9zAdLz35iY92/a9UgGzRPMBPuulHNUbcIzDT9mYvTe
8Tb/vvjX0byk1ru0UKBbCP0tkh5rbEDkKVQggRqqTbX0sUpledOZsO7aWmUB8RlBdU4GtYADUTOZ
om+1lA+7DqbkS12mDshaO8BaO2IhLqdCGR+8czoWEJzPO05zBPcyyLldYoToY/pOuWYZJS1VIW9V
mY/SWKsjNESk7Iv3j8JM5THh7i5e9ilvkZjstGuIS7uuQZH8kM9MepZU7nd/d29CaLCyVaidHtwR
LlTRLBz8Fthp4PDse1wZVLSGbA7ECuy6jFhUKr04cPeSNUYO5cuAM4SWLD70We75In67GxF/OOt+
8j//VX5NYG4n+3/j6MNtgET+llFtg6qjRauiJn11lo3GBDuCWN2nwaWJhHp893EMiMossKp8DWM9
gHGTXAGSL4zC5+6LSVSH8WJYSsWNcd6rFwT7g96wZYvhxRUXIF9lxP4oV74Yx8ZVbMx4ZMfL03Ya
m/tF56qcARms3vLE3CUVZUtRr7U2baH2VOjTI9MB3RPdE5C9yPmoyPCxrLmqtitXPzNYSzdf6j7a
aAd7U3imqOnPvW70qBNAI2ZCNVJN9SLKQM5JT8bz5Znd5clnSWaI8YdzMedESR7ywtcgUv76xyrF
L7UCq3CdF6kBZkViOj3hdTMvo/xdqwRSPP7OohH1BuBK9Xwo/LZtHJmE8ISd/BX/VSn+Xn3rmhF4
QFZ9pHhMwazEqyeQ0IngvXyQoFeOJBkVnVSbyl13x8OhxbxIAyq2hio147JEpozC+eZ0ZHHpFfta
x+qr/JVuU6Tdbf2NKMjTIipKIKbkAnOfF/+wjglQVLgULFG3P81vr4m8sFSOG1Z7XdyloJJ5Vwvv
piy5bcfVC3ScTusVh6Ccv1gLlLYoSQTf6x6gL+tX43Z6Q6ZWZfvdTDRAtt/q86XHN6b1oYQ8XqXT
iu2bE6e82MBTo6sTwbe8W2cbtRBesUHyWKnwhhOFQQzr9eVvzceLyV/9NZqP1dSO/mlvxRMlrgh2
dsEsUXmr3ptTkxrkaEMwR77DWfeT/4f/Rjb/xj0Ot+GH/yDK/fa0PRAcbO1Yp77z2Ko/mChKPR8x
BeBnqbRJIzu2dTgWjBkruUqXgMVNkmXLFlCVXDDrr544EXBycrj/bQGTvaD5Xxhi5XFMJQ90ABCb
u21xj98PkLDRo1KpnMnT5MgZac7wXbkFmuGkwjB+/fnb4+pu8S9SfddW7FB78cme+qu3eg3ALqYH
TBX75FcaKEN7hIqRZtVmWj/jdyZAN8ZlELqbKzD33aCU7gn8gPZpWjUuUcn3ceWArEfJ444p0Fw5
pSLLvMAGmw9/oJDbIM+w9N1rQQ+sxPYUrkQZeIxeDrTXxYnm6T1LffRCdMaVqr5ObS1Wxbnu0wKw
JWFnDuv/P7kyh1k="""))


def get_content_index(count):
    # this is a disaster
    # but this will just get longer and longer...
    # i'll figure out a better way to do this later
    content_index = 0
    content_index_string = ""
    content_index_offset = 0
    for i in range(count):
        if int(content_index) == 0xFF:
            content_index = 0
            content_index_string += "FF"
            content_index_offset = 0
        content_index += (0x80 / (2 << content_index_offset)) * 2
        content_index_offset += 1
    return content_index_string + format(int(content_index), 'X')


# http://stackoverflow.com/questions/8866046/python-round-up-integer-to-next-hundred
def roundup(x, base=64):
    return x if x % base == 0 else x + base - x % base


def showprogress(val, maxval):
    # crappy workaround I bet, but print() didn't do what I wanted
    minval = min(val, maxval)
    sys.stdout.write("\r- {:>5.1f}% {:>10} / {}".format((minval / maxval) * 100, minval, maxval))
    sys.stdout.flush()

keys = []
with open("decTitleKeys.bin", "rb") as f:
    key_count = struct.unpack("<H", f.read(2))[0]
    f.seek(0x10)
    keys_raw = f.read((key_count * 0x20))
    for key_offset in range(key_count):
        keys.append([
            # titlekey
            keys_raw[(key_offset * 0x20) + 0x10:(key_offset * 0x20) + 0x20],
            # title id high
            keys_raw[(key_offset * 0x20) + 0x8:(key_offset * 0x20) + 0xC],
            # title id low
            keys_raw[(key_offset * 0x20) + 0xC:(key_offset * 0x20) + 0x10],
            # common key index
            keys_raw[(key_offset * 0x20)]
        ])

os.makedirs("cia", exist_ok=True)
for key in keys:
    tid_high = binascii.hexlify(key[1]).decode('utf-8')
    tid_low = binascii.hexlify(key[2]).decode('utf-8')
    ticket_path = "tickets/{}{}.tik".format(tid_high, tid_low)
    content_path = "title/{}/{}/content".format(tid_high, tid_low)
    if not (os.path.isdir(content_path) or os.path.isfile(ticket_path)):
        continue

    # assuming there is just one tmd. usually there is only one, so there's no real need to check for more.
    tmd_files = glob.glob(content_path + "/*.tmd")
    if len(tmd_files) == 0:
        continue

    tmd = b''
    with open(tmd_files[0], "rb") as f:
        tmd = f.read()

    # separate Content chunk records for easier reading
    content_count = struct.unpack(">H", tmd[0x1DE:0x1E0])[0]
    content_chunk_records = tmd[0xB04:0xB04 + (content_count * 0x30)]

    # contents order: [ID, index, type, size]
    contents = []
    content_total_size = 0
    for c in range(content_count):
        offset = (c * 0x30)
        content_size = struct.unpack(">Q", content_chunk_records[0x8 + offset:0x10 + offset])[0]
        content_total_size += content_size
        contents.append([
            # ID
            binascii.hexlify(content_chunk_records[0x0 + offset:0x4 + offset]).decode('utf-8'),
            # index
            content_chunk_records[0x4 + offset:0x6 + offset],
            # type
            struct.unpack(">H", content_chunk_records[0x6 + offset:0x8 + offset])[0],
            # size
            content_size
        ])

    print("Title ID:            {}{}".format(binascii.hexlify(key[1]).decode('utf-8'), binascii.hexlify(key[2]).decode('utf-8')))
    print("Decrypted Titlekey:  {}".format(binascii.hexlify(key[0]).decode('utf-8')))
    print("TMD Content Count:   {}".format(content_count))
    print("Total content size:  {:016X}".format(content_total_size))
    print()

    ticket = b''
    with open(ticket_path, "rb") as f:
        ticket = f.read(0x350)

    with open("cia/{}{}.cia".format(tid_high, tid_low), "wb") as cia:
        print("Writing CIA header...")
        cia.write(
            # sizes of archive header + cert chain + ticket
            binascii.unhexlify("2020000000000000000A000050030000") +
            # tmd size + meta size (zero since the region doesn't exist)
            struct.pack("<II", len(tmd), 0) +
            # content size
            struct.pack("<Q", content_total_size) +
            # content index
            binascii.unhexlify(get_content_index(content_count)).ljust(0x2020, b'\0') +
            # cert chain
            certificate_chain +
            # ticket + padding
            ticket + (b'\0' * 48) +
            # tmd + padding
            tmd.ljust(roundup(len(tmd)), b'\0')
        )
        for c in contents:
            do_encrypt = c[2] & 1
            cipher_content = AES.new(key[0], AES.MODE_CBC, c[1] + (b'\0' * 14))
            if do_encrypt:
                print("Encrypting & writing {}...".format(c[0]))
            else:
                print("Writing {}...".format(c[0]))

            left = c[3]  # set to current size
            with open("{}/{}.app".format(content_path, c[0]), "rb") as f:
                for __ in itertools.repeat(int(math.floor((c[3] / readsize)) + 1)):
                    to_read = min(readsize, left)
                    content = f.read(to_read)
                    if do_encrypt:
                        content = cipher_content.encrypt(content)
                    cia.write(content)
                    left -= readsize
                    showprogress(c[3] - left, c[3])
                    if left <= 0:
                        print()
                        break
    print()
