# tk840upload

`tk840upload` is the write-side companion to `tk840dump` for the Kenwood TK-840 family.

Build:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk840upload tk840upload.c
```

Usage:

```sh
./tk840upload /dev/ttyUSB0 codeplug codeplug.bin
./tk840upload /dev/ttyUSB0 firmware firmware.bin
./tk840upload --dry-run /dev/ttyUSB0 firmware firmware.bin
./tk840upload --force-unsafe /dev/ttyUSB0 codeplug codeplug.bin
```

The codeplug image must be exactly `0x1800` bytes for CPU addresses `E600-FDFF`. The firmware image must be exactly `0x6600` bytes for `8000-E5FF`.

## Codeplug writes

The program reads the complete live codeplug first, compares it with the input image, and writes only changed `0x80`-byte blocks using the verified KPG-25D `W` transaction. Each changed block is read back immediately, then the complete codeplug is read back and compared byte-for-byte.

By default, codeplug byte `E66C` bit 2 is forced on. Thus a supplied codeplug that clears the recovery bit is not written literally unless `--force-unsafe` is used.

## Firmware writes

The program first reads the complete live firmware and compares it to the input image in native AT29C256 `0x40`-byte pages. Only changed pages are sent to the resident firmware loader.

Before entering the loader, the program normally reads the first codeplug block, forces `E66C` bit 2 on if necessary, writes that block, and verifies it. `--force-unsafe` suppresses this automatic recovery interlock and permits firmware programming with the bit clear.

The firmware loader path was decoded from the TK-840 mask ROM. Its first received serial byte selects the ASCII-HEX path and is discarded, so `tk840upload` sends a sacrificial carriage return before the first record. The loader then accepts addressed ASCII-hex data records; four 16-byte records make one 64-byte Flash page. This makes sparse firmware updates possible. The uploader sends a zero-length record to finalize the loader transaction.

The firmware image is also required to contain `KENWOOD` at CPU address `E580`, unless `--force-unsafe` is used.

After programming, the program asks for a normal power-cycle, re-enters PROGRAM mode, reads `8000-E5FF`, and requires an exact byte-for-byte match before reporting success.

## Recovery-mode entry

The common mask ROM gates panel event `0x84` with codeplug `E66C` bit 2. The documented TK-941 FPRO procedure enters firmware programming by holding **SYSTEM UP** while powering on until the display shows `PROG`. `tk840upload` pauses and asks you to enter this mode before it sends firmware records.

## Password-protected radios

If the radio identification ends in `Y`, `tk840upload` reads `E600-E67F`, retrieves the literal ten-byte programming password from `E670-E679`, and authenticates using command `04h`. It does not erase or modify the password as part of login.

## Status

The ordinary codeplug `W` protocol and readback behavior have already been exercised on TK-840 hardware through the CHIRP work. The first resident firmware-loader bench test confirmed the four-record page buffering and exposed the required sacrificial sync byte. The corrected firmware path still needs a successful hardware retest. Use `--dry-run` first.
