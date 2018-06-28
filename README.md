# hacbuild
hacbuild is a Work-In-Progress utility to rebuild *Switch GameCards* (XCI) from scratch.

## Overview

### Usage
- `hacbuild hfs0 <in_folder> <out_file>` Builds a hfs0 partition
- `hacbuild xci <in_folder> <out_file>` Builds a XCI from a directory containing 'root.hfs' and 'game_info.ini' (optional)
- `hacbuild xci_auto <in_folder> <out_file>` Builds a XCI from a directory containing the folders 'normal', 'secure', 'update' and 'logo' if needed. 'game_info.ini' is also used.
- `hacbuild read xci <in_file>` Reads a XCI, displays info on the console and dumps the game .ini configuration (for `game_info.ini`) in the working directory.

The program will automatically seek a `keys.txt` file in the working directory in order to gather the only key needed: `XCI Header Key` (`xci_header_key = 01C5...`)

### Functionalities
- Rebuilds the XCI format 
- Rebuilds HFS0 partitions (with less padding than the official ones)
- Reads XCI files to obtain informations needed to rebuild them
- Can ULTRA-trim (still experimental) XCIs by removing the entirety of the update partition (leaving at least one file) and having less padded HFS0

### Limitations
- Can't generate a valid RSA signature for the XCI, so they can only be loaded with kernel patches
- Still can't figure out the usefulnes of some fields
- Due to NCAs signature checks we still can't modify games (for example eShop titles can be mashed into a XCI but they will still require a ticket)
- The coding is quite dirty and it lacks pretty much any exception handling. Use with care

## Help needed 

We have pushed hacbuild to a state where it can build valid XCI files, but there is still very much to do. Since we know the potential is there, we'd like people to contribute to the project.




