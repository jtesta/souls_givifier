# Souls Givifier

This tool edits save-game files from various FromSoftware games, and grants 1 billion souls/runes in order to max out all stats (STR = 99, DEX = 99, etc.).  This lowers the bar so more casual players can enjoy the phenomenal artwork and storytelling these games are known for.

The following games are currently supported (*PC only*):
* Dark Souls Remastered
* Dark Souls II: Scholar of the First Sin
* Dark Souls III
* Elden Ring

## Usage

There are two methods of editing save files.  The main method is using the Javascript code through a browser (a live version is available at [https://jtesta.github.io/souls_givifier/](https://jtesta.github.io/souls_givifier/)); this has the advantages of being highly accessible to non-technical users and without needing to run shady programs/malware.

The alternate method is using the Python command-line program (see [souls_givifier.py](https://github.com/jtesta/souls_givifier/blob/master/souls_givifier.py)).

The general workflow is:
1. Start a new game (if you don't have a save file already).
2. Exit the game.
3. Locate the `*.sl2` file that contains the save info (instructions are found in the browser-based tool).
4. Make a backup of the `*.sl2` files in case it becomes corrupted during this process.
5. Use your browser (or command line tool) to set the number of held souls/runes to 999,999,999.
6. Replace the original `*.sl2` file with your edited version.
7. Start the game back up, then max out all your stats.
8. Beat *all bosses* in three tries or less!  And enjoy the scenery without the frustration!

A video showing the editing process for Elden Ring is here: [https://youtu.be/PZCt8gPkr_k](https://youtu.be/PZCt8gPkr_k)

## Screenshots

**Dark Souls Remastered:**
![DSR1](/screenshots/dsr_1.png)
![DSR1](/screenshots/dsr_2.png)

**Dark Souls II: Scholar of the First Sin:**
![DS2](/screenshots/ds2_1.png)
![DS2](/screenshots/ds2_2.png)

**Dark Souls III:**
![DS3](/screenshots/ds3_1.png)
![DS3](/screenshots/ds3_2.png)

**Elden Ring:**
![ER](/screenshots/er_1.png)
![ER](/screenshots/er_2.png)

## References

Parts of this project's code were based on [Michał Gębicki's SL2Bonfire codebase](https://github.com/mi5hmash/SL2Bonfire).
