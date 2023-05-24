var original_filename = "";
var save_game_loaded = false;


/* On page load, set some listener events for the UI. */
window.onload = function onBodyLoad(e) {

    // Add a listener for when the user selects the game type.
    var game_type_combobox = document.getElementById("game_type_combobox");
    game_type_combobox.addEventListener("change", (event) => {
        var game_type = document.getElementById("game_type_combobox").value;
        const the_file = document.getElementById("the_file");
        if (game_type !== "invalid") {
            the_file.disabled = false;
            update_status("Select the *.sl2 file to modify.");
        } else {
            the_file.disabled = true;
            the_file.value = "";
            update_status("Select the game type.");
        }

        // Update the instructions for obtaining the SL2 file for the selected game type.
        update_instructions(game_type);
    });

    // Add a listener for when the user selects a file.
    const the_file = document.getElementById("the_file");
    the_file.addEventListener("change", (event) => {
        const file_list = event.target.files;
        const reader = new FileReader();

        // When the file is done being loaded, call file_loaded() on the bytes.
        reader.addEventListener("load", (event) => {
            file_loaded(the_file.value, event.target.result);
        });

        // Start the asynchronous file read.
        reader.readAsArrayBuffer(file_list[0]);
    });

    // Add a click listener for the save button.
    const save_button = document.getElementById("save_button");
    save_button.addEventListener("click", function (event) { save_file(); });

    // Disable controls until the user follows the intended flow.
    reset_ui(true);
}


function file_loaded(filename, data) {
    console.log("file_loaded(" + filename + ") called.");

    // Get the base name of the filename.  i.e.: "C:\dir\file.sl2" => "file.sl2"
    original_filename = filename;
    var last_slash_pos = original_filename.lastIndexOf("\\");
    if (last_slash_pos == -1) {
        last_slash_pos = original_filename.lastIndexOf("/");
    }

    if (last_slash_pos != -1) {
        original_filename = original_filename.slice(last_slash_pos + 1);
    }

    // Get the game type that the user selected.
    var game_type = document.getElementById("game_type_combobox").value;

    if (game_type == "invalid") {
        alert("Before loading the save game file, you must choose the game type.");
        return;
    }

    file_loaded_async(game_type, filename, data);
}


/* Process the raw file data. */
async function file_loaded_async(game_type, filename, data) {

    // Convert from ArrayBuffer to Uint8Array.
    raw_file_data = new Uint8Array(data);

    // Remove all options from the save slot combobox.
    var save_slot_combobox = document.getElementById("save_slot_combobox");
    while (save_slot_combobox.firstChild) {
        save_slot_combobox.removeChild(save_slot_combobox.firstChild);
    }

    var slot_occupancy = await load_save_game(game_type, raw_file_data);
    console.log("slot_occupancy (from load_save_game()): " + JSON.stringify(slot_occupancy));

    var option = document.createElement("option");
    option.value = -1;
    option.innerHTML = "All slots";
    save_slot_combobox.appendChild(option);

    var found_non_ascii_name = false;
    for (slot in slot_occupancy) {
        var character_name = slot_occupancy[slot];
        option = document.createElement("option");
        option.value = slot;
        option.innerHTML = "Save slot " + slot + ": " + character_name;
        save_slot_combobox.appendChild(option);

        // Check if the name contains a non-ASCII printable character.
        if (!is_ascii(character_name)) {
            found_non_ascii_name = true;
        }
    }

    save_slot_combobox.disabled = false;
    save_game_loaded = true;

    document.getElementById("save_button").disabled = false;

    // If non-ASCII printable characters were found in the name, and the game type is DS3 or ER, print a warning that this may not work.  These games seem to use variable offsets, so our workaround is to search the character names in the save game data, and use that as a relative offset.  This search step may fail with non-ASCII characters, unfortunately.
    if (found_non_ascii_name && ((game_type == "ds3") || (game_type == "er"))) {
        update_status("WARNING: your character name contains non-ASCII characters.  Modifying the save game may not work.  If it fails, please contact jtesta@positronsecurity.com for help.");
    } else {
        update_status("Ready to modify save game.  Click the \"Modify Save File\" button when ready.");
    }
    return;
}


/* Returns true if all characters in a string are ASCII-printable, otherwise false. */
function is_ascii(str) {
    var ascii_code = 0;
    for (var i = 0; i < str.length; i++) {
        ascii_code = str.charCodeAt(i);
        if ((ascii_code < 32) || (ascii_code > 126))
            return false;
    }
    return true;
}


// Resets the UI back to its original state.
function reset_ui(reset_status) {
    original_filename = "";
    save_game_loaded = false;

    // Reset the game type selector to index 0.
    document.getElementById("game_type_combobox").selectedIndex = 0;

    // Disable the SL2 file selector.
    const the_file = document.getElementById("the_file");
    the_file.value = "";
    the_file.disabled = true;

    // Disable the save slot selector.
    document.getElementById("save_slot_combobox").disabled = true;

    // Reset the number of souls textbox.
    document.getElementById("num_souls").value = 999999999;

    // Uncheck the backup confirmation checkbox.
    document.getElementById("backup_checkbox").checked = false;

    // Disable the save button.
    document.getElementById("save_button").disabled = true;

    // Reset the status field.
    if (reset_status) {
        update_status("Select the game type.");
    }
}


async function save_file() {

    if (document.getElementById("backup_checkbox").checked == false) {
        alert("You must acknowledge that you made a backup of your save file before continuing.");
        return;
    }

    // Get the slot number to modify.  The 'all' entry will have a value of -1.
    var slot_num = document.getElementById("save_slot_combobox").value;

    // Get the number of souls to set the slot(s) to.
    var num_souls = document.getElementById("num_souls").value;

    console.log("Calling modify_entries(" + slot_num + ")...");
    var modified_sl2 = await modify_entries(slot_num, num_souls);
    console.log("modify_entries() returned with " + modified_sl2.byteLength + " bytes.");

    // Cause the new file to be downloaded by the browser.
    const downloader = document.createElement("a");
    downloader.style.display = "none";
    document.body.appendChild(downloader);

    downloader.href = window.URL.createObjectURL(new Blob([modified_sl2], {type: "application/octet-stream"}));
    downloader.download = original_filename;
    downloader.click();
    window.URL.revokeObjectURL(downloader.href);
    document.body.removeChild(downloader);

    // Update the status.
    update_status("<b>File successfully modified!  Check download folder for " + original_filename + ".</b>");

    // Reset the UI back to its original state.
    reset_ui(false);
}


// Updates the instruction field with specific instructions on obtaining the SL2 file for the selected game type.
function update_instructions(game_type) {
    const instructions = document.getElementById("instructions");

    var s = "(select game type, above)";
    if (game_type == "dsr") {
        s = "For new games, make your way to Firelink Shrine first.  For both new and existing saves, be sure to quit the game, then find the DRAKS0005.sl2 file in \"C:\\Users\\&lt;username&gt;\\Documents\\NBGI\\DARK SOULS REMASTERED\\&ltdirectory_of_numbers&gt;\\\".";
    } else if (game_type == "ds2") {
        s = "For new games, make your way to the Majula bonfire.  For both new and existing saves, be sure to quit the game, then find the DS2SOFS0000.sl2 file in \"C:\\Users\\&lt;username&gt;\\AppData\\Roaming\\DarkSoulsII\\&ltdirectory_of_numbers_and_letters&gt;\\\".";
    } else if (game_type == "ds3") {
        s = "For new games, make your way to Firelink Shrine first.  For both new and existing saves, be sure to quit the game, then find the DS30000.sl2 file in \"C:\\Users\\&lt;username&gt;\\AppData\\Roaming\\DarkSoulsIII\\&ltdirectory_of_numbers_and_letters&gt;\\\".";
    } else if (game_type == "er") {
        s = "For new games, make your way to the site of grace outside of StormVeil Castle first.  For both new and existing saves, be sure to quit the game, then find the ER0000.sl2 file in \"C:\\Users\\&lt;username&gt;\\AppData\\Roaming\\EldenRing\\&ltdirectory_of_numbers_and_letters&gt;\\\".";
    }
    console.log(s);
    instructions.innerHTML = s;
}


// Updates the 'Status' field.
function update_status(s) {
    document.getElementById("status").innerHTML = s;
}
