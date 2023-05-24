#!/usr/bin/env python3
'''
souls_givifier.py
Copyright 2023  Joe Testa <jtesta@positronsecurity.com>

This program is free software: you can redistribute it and/or modify
it under the terms version 3 of the GNU General Public License as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.



This tool will edit Dark Souls 1, 2, 3, and Elden Ring SL2 files and give your character 1 billion souls.  This is more than enough to max out all stats (STR = 99, DEX = 99, etc), making the game MUCH easier.

The only requirement is the cryptography module.  Install with 'pip3 install --user -U cryptography'.

This tool was made possible by the excellent work done by Michał Gębicki in <https://github.com/mi5hmash/SL2Bonfire>.
'''

import argparse
import hashlib
import os
import struct
import sys

from typing import Dict, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# The key to decrypt SL2 files from Dark Souls Remastered.
DSR_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'

# The key to decrypt SL2 files from Dark Souls 2: Scholar of the First Sin.
DS2_KEY = b'\x59\x9f\x9b\x69\x96\x40\xa5\x52\x36\xee\x2d\x70\x83\x5e\xc7\x44'

# The key to decrypt SL2 files from Dark Souls III.
DS3_KEY = b'\xfd\x46\x4d\x69\x5e\x69\xa3\x9a\x10\xe3\x19\xa7\xac\xe8\xb7\xfa'

# When set with -d/--debug, program will output debugging info.
DEBUG_MODE = False

# Denotes the game that generated the SL2 input file.  Set to one of: 'dsr', 'ds2', 'ds3', 'er'.
GAME = ''


def bytes_to_intstr(byte_array: bytes) -> str:
    '''Converts bytes into a comma-separated list of ascii integer values.  Useful for debugging against Javascript Uint8Arrays.'''
    ret = ''

    for _, i in enumerate(byte_array):
        ret += "%u," % i

    return ret[0:-1]


def debug(msg: str = '') -> None:
    '''When debugging mode is enabled, the string argument is printed to stdout.'''
    if DEBUG_MODE:
        print(msg)


class BND4Entry:  # pylint: disable=too-many-instance-attributes
    '''Represents a BND4 entry inside an SL2 file.  Handles decryption, modification, and re-encryption.'''

    def __init__(self, _raw: bytes, _index: int, _decrypted_slot_path: Optional[str], _size: int, _data_offset: int, _name_offset: int, _footer_length: int) -> None:
        self.raw = _raw
        self.index = _index
        self._decrypted_slot_path = _decrypted_slot_path
        self.size = _size
        self.data_offset = _data_offset
        self.name_offset = _name_offset
        self.footer_length = _footer_length

        self._name = self.raw[self.name_offset:self.name_offset + 24].decode('utf-16')
        self._iv = self.raw[self.data_offset + 16:self.data_offset + 32]
        self._encrypted_data = self.raw[self.data_offset + 16:self.data_offset + self.size]
        self._decrypted_data = b''

        self._checksum = self.raw[self.data_offset:self.data_offset + 16]
        self.decrypted = False
        self._decrypted_data_length = 0

        self.character_name = ''
        self.occupied = False

        debug("IV for BNDEntry #%u: %s" % (self.index, bytes_to_intstr(self._iv)))


    def custom_pkcs7_padding(self) -> bytes:
        '''Returns some kind of customized PKCS#7 padding.'''

        pad_len = 16 - ((len(self._decrypted_data) + 4) % 16)

        # If it was already aligned to the block size (16), then no padding needed.
        if pad_len == 16:
            return b''

        return struct.pack('B', pad_len) * pad_len


    def decrypt(self) -> None:
        '''Decrypts this BND4 entry, and sets the character_name member if this slot is occupied with save data.'''


        if GAME == 'er':
            self._decrypted_data = self._encrypted_data
            self._decrypted_data_length = len(self._decrypted_data)
        else:
            # Decrypt with AES-128 in CBC mode.
            key = DSR_KEY
            if GAME == 'ds2':
                key = DS2_KEY
            elif GAME == 'ds3':
                key = DS3_KEY

            decryptor = Cipher(algorithms.AES128(key), modes.CBC(self._iv)).decryptor()
            self._decrypted_data = decryptor.update(self._encrypted_data) + decryptor.finalize()

            # The length of the decrypted record is an integer at offset 16-20.
            self._decrypted_data_length = struct.unpack("<i", self._decrypted_data[16:20])[0]

            # Skip the first 16 bytes (that's the IV that was decrypted into meaningless data), and also skip the length field we read above.
            self._decrypted_data = self._decrypted_data[20:]

            # There is some postfix that should be removed.
            self._decrypted_data = self._decrypted_data[0:self._decrypted_data_length]

        # If the user wants us to save the decrypted slot data, now's the time...
        if self._decrypted_slot_path is not None:

            # Create the output directory if it does not already exist.
            if not os.path.isdir(self._decrypted_slot_path):
                debug("Decrypted slot path %s does not exist.  Creating it..." % self._decrypted_slot_path)
                os.makedirs(self._decrypted_slot_path)

            slot_full_path = os.path.join(self._decrypted_slot_path, self._name)
            debug("Writing decrypted data to %s..." % slot_full_path)
            with open(slot_full_path, 'wb') as output:
                output.write(self._decrypted_data)

        # Set the decrypted flag.
        self.decrypted = True


    def encode_char_name(self) -> bytes:
        '''Insert zero bytes in between each character.  This is how the character name appears in the decrypted data.  (Python's utf-16 encoder results in very different results so we can't use that.)'''

        name_bytes = b''
        for char in self.character_name:
            name_bytes += (char.encode('ascii') + b'\x00')

        return name_bytes


    def unified_get_slot_occupancy(self) -> Dict[int, str]:
        '''For Dark Souls Remastered, Dark Souls III, and Elden Ring saves, reads the 11th BND4 entry to determine which save slots are occupied.'''

        if self.index != 10:
            print("ERROR: unified_get_slot_occupancy() can only be called on entry #10!")
            sys.exit(-1)

        if not self.decrypted:
            self.decrypt()

        _slot_occupancy = {}
        slot_bytes = b''
        slot_data_offset = 0
        slot_length = 0
        name_max_len = 0
        if GAME == 'dsr':
            slot_bytes = self._decrypted_data[176:186]
            slot_data_offset = 192
            slot_length = 400
            name_max_len = 13
        elif GAME == 'ds3':
            slot_bytes = self._decrypted_data[4244:4254]
            slot_data_offset = 4254
            slot_length = 554
            name_max_len = 16
        elif GAME == 'er':
            slot_bytes = self._decrypted_data[6484:6494]
            slot_data_offset = 6494
            slot_length = 588
            name_max_len = 16

        for i in range(0, 10):
            # If this slot is marked as occupied...
            if slot_bytes[i:i + 1] != b'\x00':

                # Pull out the character's name for this slot number.
                name_offset = slot_data_offset + (slot_length * i)
                name_bytes = self._decrypted_data[name_offset:name_offset + (name_max_len * 2)]

                # Find the null byte, and truncate after that point.
                null_pos = name_bytes.find(b'\x00\x00')
                if null_pos != -1:
                    name_bytes = name_bytes[0:null_pos + 1]

                _slot_occupancy[i] = name_bytes.decode('utf-16')

        debug("unified_get_slot_occupancy() returning: %s" % _slot_occupancy)
        return _slot_occupancy


    def ds2_get_slot_occupancy(self) -> Dict[int, str]:
        '''For Dark Souls II saves, reads the first BND4 entry to determine which save slots are occupied.'''

        if self.index != 0:
            print("ERROR: ds2_get_slot_occupancy() can only be called on entry #0!")
            sys.exit(-1)

        if not self.decrypted:
            self.decrypt()

        _slot_occupancy = {}
        for index in range(0, 10):
            if self._decrypted_data[892 + (496 * index)] == 76:
                name_offset = 1286 + (496 * index)
                name_bytes = self._decrypted_data[name_offset:name_offset + (14 * 2)]

                # If the name bytes contain a null byte, truncate it and everything after.
                null_pos = name_bytes.find(b'\x00\x00')
                if null_pos != -1:
                    name_bytes = name_bytes[0:null_pos + 1]

                _slot_occupancy[index + 1] = name_bytes.decode('utf-16')

        debug("ds2_get_slot_occupancy() returning: %s" % _slot_occupancy)
        return _slot_occupancy


    def modify_num_souls(self, raw: bytes, num_souls: int) -> bytes:  # pylint: disable=too-complex
        '''Modifies the number of souls stored in this entry.'''


        # A previous invokation of this function may have changed the raw file bytes, so to not overwrite those changes, we update our reference here.
        self.raw = raw

        # Ensure that this entry is decrypted before doing anything else.
        if not self.decrypted:
            self.decrypt()

        key = b''
        if GAME == 'dsr':
            key = DSR_KEY

            field1 = max(struct.unpack("<I", self._decrypted_data[224:228])[0], num_souls)
            field2 = max(struct.unpack("<I", self._decrypted_data[228:232])[0], num_souls)

            self._decrypted_data = self._decrypted_data[0:224] + struct.pack("<I", field1) + struct.pack("<I", field2) + self._decrypted_data[232:]
        elif GAME == 'ds2':
            key = DS2_KEY

            # There are three adjacent locations where the souls are stored.  One of these is probably "soul memory", which is the total number of souls the player has earned in their playthrough so far.  If the existing values are greater than the number of souls we're supposed to set, leave them unchanged.  This prevents us from accidentally reducing the "soul memory" field, which might cause a corrupt save file.
            field1 = max(struct.unpack("<I", self._decrypted_data[60:64])[0], num_souls)
            field2 = max(struct.unpack("<I", self._decrypted_data[64:68])[0], num_souls)
            field3 = max(struct.unpack("<I", self._decrypted_data[68:72])[0], num_souls)

            self._decrypted_data = self._decrypted_data[0:60] + struct.pack("<I", field1) + struct.pack("<I", field2) + struct.pack("<I", field3) + self._decrypted_data[72:]
        elif GAME == 'ds3':
            key = DS3_KEY

            # Convert the character name from a string to the same byte format used in decrypted entries.
            name_bytes = self.encode_char_name()

            # Find the offset of where the character name first appears.  We'll use this offset to locate the souls fields, since apparently DS3's save file can vary in size (so static offsets don't work).
            name_pos = self._decrypted_data.find(name_bytes)
            if name_pos == -1:
                print("ERROR: could not find name in decrypted data!: %r" % name_bytes)
                sys.exit(-1)

            debug("Name found in decrypted data at offset %u." % name_pos)

            field1 = max(struct.unpack("<I", self._decrypted_data[name_pos - 20: name_pos - 16])[0], num_souls)
            field2 = max(struct.unpack("<I", self._decrypted_data[name_pos - 16: name_pos - 12])[0], num_souls)

            self._decrypted_data = self._decrypted_data[0:name_pos - 20] + struct.pack("<I", field1) + struct.pack("<I", field2) + self._decrypted_data[name_pos - 12:]
        elif GAME == 'er':

            # Convert the character name from a string to the same byte format used in decrypted entries.
            name_bytes = self.encode_char_name()

            # Find the offset of where the character name first appears.  We'll use this offset to locate the souls fields, since apparently ER's save file can vary in size (so static offsets don't work).
            name_pos = self._decrypted_data.find(name_bytes)
            if name_pos == -1:
                print("ERROR: could not find name in decrypted data!: %r" % name_bytes)
                sys.exit(-1)

            debug("Name found in decrypted data at offset %u." % name_pos)

            field1 = max(struct.unpack("<I", self._decrypted_data[name_pos - 48:name_pos - 44])[0], num_souls)
            field2 = max(struct.unpack("<I", self._decrypted_data[name_pos - 44:name_pos - 40])[0], num_souls)
            self._decrypted_data = self._decrypted_data[0:name_pos - 48] + struct.pack("<I", field1) + struct.pack("<I", field2) + self._decrypted_data[name_pos - 40:]

        if GAME == 'er':  # Elden Ring doesn't use encryption.
            self._encrypted_data = self._decrypted_data
        else:  # Other games require the slots to be re-encrypted.
            encryptor = Cipher(algorithms.AES128(key), modes.CBC(self._iv)).encryptor()

            # encrypted_data = IV + AES128-CBC(length_of_plaintext + plaintext + custom_pkcs7_padding)
            self._encrypted_data = self._iv + encryptor.update(struct.pack("<I", len(self._decrypted_data)) + self._decrypted_data + self.custom_pkcs7_padding()) + encryptor.finalize()

        # Re-calculate the checksum of the encrypted data.
        self._checksum = hashlib.md5(self._encrypted_data).digest()

        # Overwrite the checksum and encrypted data in the raw file bytes.  Since the lengths of everything stay the same, no need to recalculate other headers.
        self.raw = self.raw[0:self.data_offset] + self._checksum + self._encrypted_data + self.raw[self.data_offset + self.size:]

        # Reset the decrypted flag, since we made changes and packaged everything back up.
        self.decrypted = False
        self._decrypted_data = b''
        self._decrypted_data_length = 0

        print("Set souls in slot #%u (character name: \"%s\") to %u." % (self.index, self.character_name, num_souls))
        return self.raw


    def set_character_name(self, name: str) -> None:
        '''Sets the name of this character.'''

        self.character_name = name
        self.occupied = True
        debug("set_character_name(%s) called on entry #%u." % (name, self.index))


    def _no_longer_used_set_occupancy(self) -> None:
        '''No longer in use.  Leaving it here just in case.  Sets the occupancy flag for this entry, and decodes the character name.'''

        debug("set_occupancy() called on entry #%u." % self.index)
        self.occupied = True

        name_offset = name_max_len = 0
        if GAME == 'dsr':
            name_offset = 244
            name_max_len = 13
        elif GAME == 'ds2':
            name_offset = 960
            name_max_len = 14
        elif GAME == 'ds3':
            name_offset = 71220
            name_max_len = 16
        elif GAME == 'er':
            name_offset = 41826
            name_max_len = 16

        # Read twice the number of the max length, since its UTF-16 encoded (meaning a null byte exists between each ASCII character).
        name_bytes = self._decrypted_data[name_offset:name_offset + (name_max_len * 2)]

        # DSR doesn't use a fixed length name field.  So we'll look for any null byte pairs, and truncate from there onwards.
        null_bytes_pos = name_bytes.find(b'\x00\x00')
        if null_bytes_pos != -1:
            name_bytes = name_bytes[0:null_bytes_pos + 1]

        self.character_name = name_bytes.decode('utf-16')
        debug("Entry #%u has character name: [%s]" % (self.index, self.character_name))


parser = argparse.ArgumentParser(description='Edits the souls held in Dark Souls SL2 save files.')
parser.add_argument('game', choices=['dsr', 'ds2', 'ds3', 'er'], help='the game that the *.sl2 input file belongs to.  dsr=Dark Souls Remastered; ds2=Dark Souls II: Scholar of the First Sin; ds3=Dark Souls III; er=Elden Ring')
parser.add_argument('input_sl2', metavar='input.sl2', help='the SL2 save file to use as input (this will not be modified).')
parser.add_argument('-d', '--debug', action='store_true', default=False, help='enable debugging messages.')
parser.add_argument('-k', '--keep-decrypted-slots', metavar='/path/to/dir', help='save decrypted slots to the specified directory.  Useful only for debugging.')
parser.add_argument('-l', '--list-slots', action='store_true', help='list the active slots in the input SL2 file.')
parser.add_argument('-o', '--output', metavar='output.sl2', help='path to write output SL2 file.  Required when -l/--list-slots is not used.')
parser.add_argument('-n', '--num-souls', metavar='N', default=999999999, type=int, help='number of souls to set (default is 999999999).')
parser.add_argument('-s', '--slot', type=int, default=-1, help='edit the specified slot only (use -l/--list-slots to see available options).  If this argument is not specified, all slots will be modified.')
args = parser.parse_args()


GAME = args.game
input_sl2_file = args.input_sl2
output_sl2_file = args.output
DEBUG_MODE = args.debug
decrypted_slot_path = args.keep_decrypted_slots

# If the user provided a negative number, or a number above the max supported by the game, error out.
if args.num_souls < 1 or args.num_souls > 999999999:
    print("ERROR: number of souls must be between 1 and 999,999,999 (the max supported by the game)")
    sys.exit(-1)

# Ensure that the slot number is between 0 and 10, or -1 (meaning all slots).
if (args.slot > 10) or (args.slot < -1):
    print("ERROR: the slot number must be between 0 and 10.")
    sys.exit(-1)

# Ensure that an output file was provided if -l/--list-slots wasn't used.
if args.list_slots is False and output_sl2_file is None:
    print("ERROR: -o/--output is required when -l/--list-slots is not used.")
    sys.exit(-1)

# If the user wants to list the slots, ensure they didn't also set the output file.  No modifications are made while listing slots, so this doesn't make sense.
if args.list_slots is True and output_sl2_file is not None:
    print("ERROR: -o/--output and -l/--list-slots are exclusive to each other.  Listing slots does not make any modifications, so an output path is not needed.")
    sys.exit(-1)

if (output_sl2_file is not None) and (args.slot == -1):
    print("All slots will be modified and their number of souls will be set to %u." % args.num_souls)
elif output_sl2_file is not None:
    print("Slot #%u will be modified only, and its number of souls will be set to %u." % (args.slot, args.num_souls))

raw = b''  # pylint: disable=invalid-name
with open(input_sl2_file, 'rb') as f:
    raw = f.read()

debug("Read %u bytes from %s." % (len(raw), input_sl2_file))
if raw[0:4] != b'BND4':
    print("ERROR: 'BND4' header not found!")
    sys.exit(-1)
else:
    debug("Found BND4 header.")

num_bnd4_entries = struct.unpack("<i", raw[12:16])[0]
debug("Number of BND4 entries: %u" % num_bnd4_entries)

unicode_flag = (raw[48] == 1)
debug("Unicode flag: %r" % unicode_flag)
debug()


slot_occupancy = {}
bnd4_entries = []
BND4_HEADER_LEN = 64
BND4_ENTRY_HEADER_LEN = 32

# Do the first pass over all BND4 entries to decrypt them all, and acquire the list of occupied slots.
for i in range(num_bnd4_entries):
    pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * i)
    entry_header = raw[pos:pos + BND4_ENTRY_HEADER_LEN]

    if entry_header[0:8] != b'\x50\x00\x00\x00\xff\xff\xff\xff':
        print("ERROR: entry header #%u does not match expected magic value!" % i)
        sys.exit(-1)

    entry_size = struct.unpack("<i", entry_header[8:12])[0]
    entry_data_offset = struct.unpack("<i", entry_header[16:20])[0]
    entry_name_offset = struct.unpack("<i", entry_header[20:24])[0]
    entry_footer_length = struct.unpack("<i", entry_header[24:28])[0]

    entry_name = (raw[entry_name_offset:entry_name_offset + 24]).decode('utf-8')

    debug("Entry #%u" % i)
    debug("Entry size: %u" % entry_size)
    debug("Entry data offset: %u" % entry_data_offset)
    debug("Entry name offset: %u" % entry_name_offset)
    debug("Entry footer length: %u" % entry_footer_length)
    debug("Entry name: [%s]" % entry_name)

    entry = BND4Entry(raw, i, decrypted_slot_path, entry_size, entry_data_offset, entry_name_offset, entry_footer_length)

    # Decrypt this entry.
    entry.decrypt()
    bnd4_entries.append(entry)

    # The slot occupancy data lives in different places depending on the game...
    if (GAME == 'ds2') and (i == 0):
        slot_occupancy = entry.ds2_get_slot_occupancy()
    elif (GAME in ['dsr', 'ds3', 'er']) and (i == 10):
        slot_occupancy = entry.unified_get_slot_occupancy()

    debug("--------------------------")


# If the user specified a slot they want to modify, check that it is occupied.  Otherwise, fail.
if (args.slot > 0) and (args.slot not in slot_occupancy):
    print("ERROR: slot #%u does not appear to be occupied!  Use -l/--list-slots to see slots that can be modified." % args.slot)
    sys.exit(-1)


# Now that we've built the dict of occupied slots, call set_character_name() on the corresponding entries.
for slot, name in slot_occupancy.items():
    bnd4_entries[slot].set_character_name(name)

    if args.list_slots:
        print("Slot #%u occupied; character name: [%s]" % (slot, bnd4_entries[slot].character_name))


# If the user only wants a listing of occupied slots, we just gave them that, above, so we're done.
if args.list_slots:
    sys.exit(0)


# If we arrived here, then the user wants to modify one or all the slots.
for i in range(num_bnd4_entries):
    entry = bnd4_entries[i]

    # If this slot is occupied with save data...
    if entry.occupied:

        # If the user selected a specific slot to modify and we happen to be on that slot, or if all occupied slots should be modified...
        if ((args.slot >= 0) and (i == args.slot)) or (args.slot == -1):
            debug("Modifying slot #%u..." % i)
            raw = entry.modify_num_souls(raw, args.num_souls)
        else:
            debug("Skipping slot #%u..." % i)


# Write the output SL2 file.
with open(output_sl2_file, 'wb') as output:
    output.write(raw)

print()
print("DONE!  Wrote to output file: %s" % output_sl2_file)
print()
