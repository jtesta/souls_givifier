/*
sl2_editor.js
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
*/

// Key obtained from: <https://github.com/pawREP/Dark-Souls-Remastered-SL2-Unpacker/blob/master/DSR_SL2_Unpacker/DSRSL2Unpacker.cpp>.
const DSR_ENCRYPTION_KEY = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);

// Key obtained from: <https://github.com/mi5hmash/SL2Bonfire>.
const DS2_ENCRYPTION_KEY = new Uint8Array([0x59, 0x9f, 0x9b, 0x69, 0x96, 0x40, 0xa5, 0x52, 0x36, 0xee, 0x2d, 0x70, 0x83, 0x5e, 0xc7, 0x44]);

// Key obtained from: <https://github.com/mi5hmash/SL2Bonfire>.
const DS3_ENCRYPTION_KEY = new Uint8Array([0xfd, 0x46, 0x4d, 0x69, 0x5e, 0x69, 0xa3, 0x9a, 0x10, 0xe3, 0x19, 0xa7, 0xac, 0xe8, 0xb7, 0xfa]);


var bnd4_entries = null;  // An array of BND4Entry objects.  Set by load_save_game().

// Determine if we're being run in Node.js or a browser.
var is_nodejs = false;
if (typeof window === 'undefined') {  // nodejs
    const crypto = globalThis.crypto;
    is_nodejs = true;
    console.log("nodejs detected.");
} else {  // Browser
    const crypto = window.crypto;
    console.log("Browser detected.");
}


// Represents a BND4 entry in the SL2 file.
class BND4Entry {
    constructor(game_type, key, raw_key, raw_file_data, index, size, data_offset, name_offset, footer_length) {
        this.game_type = game_type;
        this.key = key;  // The return value of Web Crypto API's importKey().
        this._raw_key = raw_key;  // The raw bytes of the key.
        this.raw_file_data = raw_file_data;
        this.index = index;
        this.size = size;
        this.data_offset = data_offset;
        this.name_offset = name_offset;
        this.footer_length = footer_length;

        // The name of this entry (such as "USER_DATA000").
        this._name = new TextDecoder('utf-16').decode(raw_file_data.slice(name_offset, name_offset + 24));

        this._checksum = raw_file_data.slice(data_offset, data_offset + 16)
        this._iv = new Uint8Array(raw_file_data.slice(data_offset + 16, data_offset + 32));
        this._encrypted_data = raw_file_data.slice(data_offset + 16, data_offset + size);
        this._decrypted_data = null;

        this.character_name = "";
        this.decrypted = false;
        this.occupied = false;  // Set to true when this entry is occupied with save game data.
    }


    // Returns some kind of customized PKCS#7 padding.
    custom_pkcs7_padding() {
        var pad_len = 16 - ((this._decrypted_data.byteLength + 4) % 16);

        // If the entire block would have been padding, return nothing.
        if (pad_len == 16)
            return new Uint8Array(0);

        var ret = new Uint8Array(pad_len);
        for (var i = 0; i < pad_len; i++)
            ret[i] = pad_len;

        return ret;
    }


    // Decrypts the encrypted entry and returns a Uint8Array.
    async decrypt() {
        console.log("[" + this.index + "] Decrypting " + this._encrypted_data.byteLength + " bytes; IV: " + this._iv);

        if (this.game_type == 'er')
            this._decrypted_data = this._encrypted_data;
        else {
            // Oddly, sometimes the Web Crypto API decrypt() function fails (against DS2 saves).  So we'll fall back on an alternate AES CBC implementation in that case.  Seems to work!
            try {
                this._decrypted_data = new Uint8Array(await crypto.subtle.decrypt({name: "AES-CBC", iv: this._iv}, this.key, this._encrypted_data));
            } catch (err) {
                console.log("WebCrypto API failed to decrypt: " + err);
                console.log("Decrypting entry " + this.index + " with aes-js instead.");

                if (is_nodejs)
                    var aesjs = require('./aes-js');

                var aescbc = new AESCBC(this._raw_key, this._iv);
                this._decrypted_data = aescbc.decrypt(this._encrypted_data);
            }

            var decrypted_data_length = unpack_uint32(this._decrypted_data, 16);
            this._decrypted_data = this._decrypted_data.slice(20).slice(0, decrypted_data_length);
        }

        this.decrypted = true;
    }


    // For Dark Souls Remastered, Dark Souls III, and Elden Ring saves, reads the 11th BND4 entry to determine which save slots are occupied.
    unified_get_slot_occupancy() {

        if (this.index != 10)
            throw new Error("unified_get_slot_occupancy() can only be called on entry #10!");

        if (!this.decrypted)
            this.decrypt();

        var _slot_occupancy = {}
        var slot_bytes = null;
        var slot_data_offset = 0;
        var slot_length = 0;
        var name_max_len = 0;
        if (this.game_type == 'dsr') {
            slot_bytes = new Uint8Array(this._decrypted_data.slice(176, 186));
            slot_data_offset = 192
            slot_length = 400
            name_max_len = 13
        } else if (this.game_type == 'ds3') {
            slot_bytes = new Uint8Array(this._decrypted_data.slice(4244, 4254));
            slot_data_offset = 4254
            slot_length = 554
            name_max_len = 16
        } else if (this.game_type == 'er') {
            slot_bytes = new Uint8Array(this._decrypted_data.slice(6484, 6494));
            slot_data_offset = 6494
            slot_length = 588
            name_max_len = 16
        } else
            throw new Error("Unknown game type: " + this.game_type);

        for (var i = 0; i < 10; i++) {
            // If this slot is marked as occupied...
            if (slot_bytes[i] != 0) {

                // Pull out the character's name for this slot number.
                var name_offset = slot_data_offset + (slot_length * i)
                var name_bytes = this._decrypted_data.slice(name_offset, name_offset + (name_max_len * 2));

                // Find the null byte, and truncate after that point.
                for (var j = 0; j < name_bytes.length - 1; j++) {
                    if ((name_bytes[j] == 0) && (name_bytes[j + 1] == 0))
                        name_bytes = name_bytes.slice(0, j + 1);
                }
                _slot_occupancy[i] = new TextDecoder('utf-16').decode(name_bytes);
            }
        }

        console.log("unified_get_slot_occupancy() returning: " + JSON.stringify(_slot_occupancy));
        return _slot_occupancy;
    }


    // For Dark Souls II saves, reads the first BND4 entry to determine which save slots are occupied.
    ds2_get_slot_occupancy() {

        if (this.index != 0)
            throw new Error("ds2_get_slot_occupancy() can only be called on entry #0!");

        if (!this.decrypted)
            this.decrypt();

        var _slot_occupancy = {}
        var data = new Uint8Array(this._decrypted_data);
        for (var i = 0; i < 10; i++) {
            if (data[892 + (496 * i)] != 0) {
                var name_offset = 1286 + (496 * i);
                var name_bytes = this._decrypted_data.slice(name_offset, name_offset + (14 * 2));

                // If the name bytes contain a null byte, truncate it and everything after.
                for (var j = 0; j < name_bytes.length - 1; j++) {
                    if ((name_bytes[j] == 0) && (name_bytes[j + 1] == 0))
                        name_bytes = name_bytes.slice(0, j + 1);
                }

                _slot_occupancy[i + 1] = new TextDecoder('utf-16').decode(name_bytes);
            }
        }

        console.log("ds2_get_slot_occupancy() returning: " + JSON.stringify(_slot_occupancy));
        return _slot_occupancy;
    }


    // Modifies the number of souls stored in this entry.
    async modify_num_souls(raw_file_data, num_souls) {
        console.log("modify_num_souls(" + num_souls + ") called on entry #" + this.index + " (" + this.character_name + ").");

        // A previous invokation of this function may have changed the raw file bytes, so to not overwrite those changes, we update our reference here.
        if (raw_file_data != null)
            this.raw_file_data = raw_file_data;

        if (!this.decrypted)
            this.decrypt();

        if (this.game_type == 'dsr') {
            var field1 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), 224));
            var field2 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), 228));

            this._decrypted_data = concat4(new Uint8Array(this._decrypted_data.slice(0, 224)), pack_integer(field1), pack_integer(field2), new Uint8Array(this._decrypted_data.slice(232)));
        } else if (this.game_type == 'ds2') {

            // There are three adjacent locations where the souls are stored.  One of these is probably "soul memory", which is the total number of souls the player has earned in their playthrough so far.  If the existing values are greater than the number of souls we're supposed to set, leave them unchanged.  This prevents us from accidentally reducing the "soul memory" field, which might cause a corrupt save file.
            var field1 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), 60));
            var field2 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), 64));
            var field3 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), 68));

            this._decrypted_data = concat5(new Uint8Array(this._decrypted_data.slice(0, 60)), pack_integer(field1), pack_integer(field2), pack_integer(field3), new Uint8Array(this._decrypted_data.slice(72)));

        } else if (this.game_type == 'ds3') {

            var name_pos = find_uint8(this._decrypted_data, str_to_bytes(this.character_name));
            if (name_pos == -1)
                throw new Error('Failed to find character name (' + this.character_name + ' in decrypted data!');

            console.log("Name found in decrypted data at offset " + name_pos);

            var field1 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), name_pos - 20));
            var field2 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), name_pos - 16));

            this._decrypted_data = concat4(new Uint8Array(this._decrypted_data.slice(0, name_pos - 20)), pack_integer(field1), pack_integer(field2), new Uint8Array(this._decrypted_data.slice(name_pos - 12)));

        } else if (this.game_type == 'er') {

            var name_pos = find_uint8(this._decrypted_data, str_to_bytes(this.character_name));
            if (name_pos == -1)
                throw new Error('Failed to find character name (' + this.character_name + ' in decrypted data!');

            console.log("Name found in decrypted data at offset " + name_pos);

            var field1 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), name_pos - 48));
            var field2 = Math.max(num_souls, unpack_uint32(new Uint8Array(this._decrypted_data), name_pos - 44));

            this._decrypted_data = concat4(new Uint8Array(this._decrypted_data.slice(0, name_pos - 48)), pack_integer(field1), pack_integer(field2), new Uint8Array(this._decrypted_data.slice(name_pos - 40)));

        } else
            throw new Error("modify_num_souls() can't modify game type of [" + this.game_type + "]!");

        if (this.game_type == 'er')
            this._encrypted_data = this._decrypted_data;
        else {
            // encrypted_data = IV + AES128-CBC(length_of_plaintext + plaintext + custom_pkcs7_padding)
            var plaintext = new Uint8Array(concat3(pack_integer(this._decrypted_data.byteLength), this._decrypted_data, this.custom_pkcs7_padding()));
            var encrypted_bytes = await crypto.subtle.encrypt({name: "AES-CBC", iv: this._iv}, this.key, plaintext);
            this._encrypted_data = concat(this._iv, encrypted_bytes.slice(0, encrypted_bytes.byteLength - 16));
        }

        // Re-calculate the checksum of the encrypted data.
        this._checksum = checksum(new Uint8Array(this._encrypted_data));

        // Overwrite the checksum and encrypted data in the raw file bytes.  Since the lengths of everything stay the same, no need to recalculate other headers.
        this.raw_file_data = concat4(this.raw_file_data.slice(0, this.data_offset), this._checksum, this._encrypted_data, this.raw_file_data.slice(this.data_offset + this.size));

        this.decrypted = false;
        this._decrypted_data = null;

        return this.raw_file_data;
    }


    // Sets the name of this character.
    set_character_name(name) {
        this.character_name = name;
        this.occupied = true;
        console.log("set_character_name(" + name + ") called on entry #" + this.index);
    }
}


function bytes_match(uint8array1, offset, num_bytes, uint8array2) {
    if (uint8array2.byteLength != num_bytes)
        return false;

    for (var i = 0; i < num_bytes; i++) {
        if (uint8array1[offset + i] != uint8array2[i])
            return false;
    }

    return true;
}


function checksum(uint8arr) {

    if (is_nodejs) {
        const md5 = require("./joes_md5");
        return md5(uint8arr);
    } else
        return md5(uint8arr);

}


function concat(a1, a2) {
    return concat5(a1, a2, null, null, null);
}


function concat3(a1, a2, a3) {
    return concat5(a1, a2, a3, null, null);
}


function concat4(a1, a2, a3, a4) {
    return concat5(a1, a2, a3, a4, null);
}


function concat5(a1, a2, a3, a4, a5) {

    // If any argument is null, initialize it to an empty Uint8Array.  If any argument is an ArrayBuffer, create a Uint8Array from it.
    if (a1 == null)
        a1 = new Uint8Array();
    else if (a1.constructor.name == 'ArrayBuffer')
        a1 = new Uint8Array(a1);

    if (a2 == null)
        a2 = new Uint8Array();
    else if (a2.constructor.name == 'ArrayBuffer')
        a2 = new Uint8Array(a2);

    if (a3 == null)
        a3 = new Uint8Array();
    else if (a3.constructor.name == 'ArrayBuffer')
        a3 = new Uint8Array(a3);

    if (a4 == null)
        a4 = new Uint8Array();
    else if (a4.constructor.name == 'ArrayBuffer')
        a4 = new Uint8Array(a4);

    if (a5 == null)
        a5 = new Uint8Array();
    else if (a5.constructor.name == 'ArrayBuffer')
        a5 = new Uint8Array(a5);

    var ret = new Uint8Array(a1.byteLength + a2.byteLength + a3.byteLength + a4.byteLength + a5.byteLength);
    ret.set(a1, 0);
    ret.set(a2, a1.byteLength);
    ret.set(a3, a1.byteLength + a2.byteLength);
    ret.set(a4, a1.byteLength + a2.byteLength + a3.byteLength);
    ret.set(a5, a1.byteLength + a2.byteLength + a3.byteLength + a4.byteLength);
    return ret;
}


/* Finds the index of the first occurance of a needle in a haystack (both Uint8Arrays).  Returns -1 if no occurance is found. */
function find_uint8(haystack, needle) {

    for (var i = 0; i < haystack.byteLength; i++) {
        var ii = i;
        for (var j = 0; j < needle.byteLength; j++, ii++) {
            if (haystack[ii] != needle[j])
                break;
        }
        if (j == needle.byteLength)
            return i;
    }

    return -1;
}


/* Converts a number into a 4-byte unsigned integer (little-endian). */
function pack_integer(num) {
    return new Uint8Array([(num & 0x000000ff), (num & 0x0000ff00) >> 8, (num & 0x00ff0000) >> 16, (num & 0xff000000) >> 24]);
}


/* Converts a string to a Uint8Array with null bytes inserted. */
function str_to_bytes(s) {
    array = [];

    for (var i = 0; i < (s.length * 2); i++)
        array[i] = 0;

    for (var i = 0; i < s.length; i++)
        array[i * 2] = s.charCodeAt(i);

    return new Uint8Array(array);
}


/* Unpacks a 32-bit unsigned integer from little-endian byte format. */
function unpack_uint32(uint8array, pos) {
    var num = 0;
    num = uint8array[pos];
    num = num | uint8array[pos + 1] << 8;
    num = num | uint8array[pos + 2] << 16;
    num = num | uint8array[pos + 3] << 24;
    return num;
}


async function load_save_game(game_type, raw_file_data) {
    console.log("load_save_game() called.  game_type is [" + game_type + "]; raw_file_data is " + raw_file_data.length + " bytes.");

    var raw_key = null;
    if (game_type == 'dsr') {
        raw_key = DSR_ENCRYPTION_KEY;
        console.log("Using DSR key.");
    } else if (game_type == 'ds2') {
        raw_key = DS2_ENCRYPTION_KEY;
        console.log("Using DS2 key.");
    } else if (game_type == 'ds3') {
        raw_key = DS3_ENCRYPTION_KEY;
        console.log("Using DS3 key.");
    } else if (game_type == 'er')
        console.log("No key selected for ER, since it doesn't encrypt its SL2 files.");
    else
        throw new Error("Game type " + game_type + " is invalid.");

    var key = null;
    if (game_type != 'er') {
        try {
            key = await crypto.subtle.importKey("raw", raw_key, "AES-CBC", true, ["encrypt", "decrypt"]);
        } catch(err) {
            throw new Error("Error while loading key!: " + err);
        }
    }

    // Ensure that the file starts with "BND4".
    const BND4_HEADER_FLAG = new Uint8Array([66, 78, 68, 52]);  // "BND4"
    if (bytes_match(raw_file_data, 0, 4, BND4_HEADER_FLAG))
        console.log("BND4 header matched.");
    else
        throw new Error("Error: file does not start with \"BND4\".  Are you sure this is a Dark Souls save game file?");


    // Get the number of BND4 entries.
    entry_count = unpack_uint32(raw_file_data, 12);
    console.log("Number of BND4 entries: " + entry_count);

    // Get the Unicode flag.
    is_unicode = false;
    if (raw_file_data[48] == 1)
        is_unicode = true;
    console.log("Unicode: " + is_unicode);


    bnd4_entries = new Array(entry_count);
    var slot_occupancy = {};
    var BND4_HEADER_LEN = 64;
    var BND4_ENTRY_HEADER_LEN = 32;

    for (var i = 0; i < entry_count; i++) {
        var pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * i);
        entry_header = raw_file_data.slice(pos, pos + BND4_ENTRY_HEADER_LEN);

        if (!bytes_match(entry_header, 0, 8, new Uint8Array([80, 0, 0, 0, 255, 255, 255, 255])))
            throw new Error("Error: entry header (" + i + ") does not match expected magic value!");

        entry_size = unpack_uint32(entry_header, 8);
        entry_data_offset = unpack_uint32(entry_header, 16);
        entry_name_offset = unpack_uint32(entry_header, 20);
        entry_footer_length = unpack_uint32(entry_header, 24);

        entry_name = new TextDecoder('utf-16').decode(raw_file_data.slice(entry_name_offset, entry_name_offset + 24));

        console.log("Entry #" + i);
        console.log("Entry size: " + entry_size);
        console.log("Entry data offset: " + entry_data_offset);
        console.log("Entry name offset: " + entry_name_offset);
        console.log("Entry footer length: " + entry_footer_length);
        console.log("Entry name: [" + entry_name + "]");

        entry = new BND4Entry(game_type, key, raw_key, raw_file_data, i, entry_size, entry_data_offset, entry_name_offset, entry_footer_length);

        await entry.decrypt();
        bnd4_entries[i] = entry;

        if (['dsr', 'ds3', 'er'].includes(game_type) && (i == 10))
            slot_occupancy = entry.unified_get_slot_occupancy();
        else if ((game_type == 'ds2') && (i == 0))
            slot_occupancy = entry.ds2_get_slot_occupancy();
    }

    // Now that we've built the dict of occupied slots, call set_character_name() on the corresponding entries to set their names.
    for (var slot in slot_occupancy) {
        entry = bnd4_entries[slot];
        entry.set_character_name(slot_occupancy[slot]);
    }

    return slot_occupancy;
}


// Modifies the entry/entries and returns the raw SL2 file.  Set argument to the entry number to modify, or -1 to modify all occupied entries.
async function modify_entries(entry_num_to_modify, num_souls) {
    var raw_file_data = null;

    for (var i = 0; i < entry_count; i++) {
        entry = bnd4_entries[i]

        // If entry_num_to_modify is -1, modify all occupied entries.  Otherwise, only modify the entry number specified.
        if (entry.occupied && ((entry_num_to_modify == -1) || (i == entry_num_to_modify))) {
            console.log("Modifying #" + entry.index + " [" + entry.character_name + "]; setting souls to " + num_souls);
            raw_file_data = await entry.modify_num_souls(raw_file_data, num_souls);
        }
    }

    return new Uint8Array(raw_file_data);
}


// The main() for nodejs runs.  Needed because we use 'await', which can't be done outside of an async function.
async function nodejs_main(game_type, input_sl2, output_sl2) {
    const fs = require('fs');
    var raw_file_data = await fs.readFileSync(input_sl2);

    var occupied_slots = await load_save_game(game_type, raw_file_data);
    raw_file_data = await modify_entries(-1, 999999999);

    fs.writeFileSync(output_sl2, raw_file_data);
}


// When running in nodejs.
if (is_nodejs) {

    if (process.argv.length != 5) {
        var err = "Usage: " + process.argv[1] + " [dsr|ds2|ds3|er] input.sl2 output.sl2";
        console.error(err);
        throw new Error(err);
    }

    var game_type = process.argv[2];
    var input_sl2 = process.argv[3];
    var output_sl2 = process.argv[4];

    if (!['dsr', 'ds2', 'ds3', 'er'].includes(game_type)) {
        var err = "ERROR: game_type must be 'dsr', 'ds2', 'ds3', or 'er'.";
        console.error(err);
        throw new Error(err);
    }

    nodejs_main(game_type, input_sl2, output_sl2);
}
