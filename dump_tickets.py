#!/usr/bin/env python3

# based on this script:
# https://github.com/d0k3/Decrypt9WIP/blob/master/scripts/dump_ticket_keys.py

import binascii
import os
import re
import struct
import sys

if not os.path.isfile("ticket.db"):
    sys.exit("ticket.db not found.")

with open("ticket.db", "rb") as f:
    ticketdb = f.read(0x237F600)

print("Finding ticket offsets...")
ticket_offsets = [m.start() for m in re.finditer(b'Root-CA00000003-XS0000000c', ticketdb)]
if len(ticket_offsets) == 0:
    sys.exit("No tickets found.")

os.makedirs("tickets", exist_ok=True)
keys = []

print("Dumping titlekeys and tickets...")
for offset in ticket_offsets:
    common_key_index = ticketdb[offset + 0xB1]
    if ticketdb[offset + 0x7C] != 1:
        continue
    if common_key_index == 0 or common_key_index > 5:  # not sure why to skip 3, but dump_ticket_keys.py does it
        continue
    title_id = ticketdb[offset + 0x9C:offset + 0xA4]
    title_id_dec = binascii.hexlify(title_id).decode('utf-8')
    print("Dumping {}...".format(title_id_dec))
    title_key = ticketdb[offset + 0x7F:offset + 0x8F]

    if [title_key, title_id, common_key_index] in keys:
        continue

    keys.append([title_key, title_id, common_key_index])

    ticket = ticketdb[offset - 0x140:offset + 0x210]
    with open("tickets/{}.tik".format(title_id_dec), "wb") as f:
        f.write(ticket)

out = struct.pack('<IIII', len(keys), 0, 0, 0)
for key in keys:
    out += struct.pack('<II', key[2], 0)
    out += key[1]
    out += key[0]

with open("encTitleKeys.bin", "wb") as f:
    f.write(out)
