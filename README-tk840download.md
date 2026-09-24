# `tk840download`

`tk840download` is a Linux/POSIX command-line utility for reading memory from Kenwood TK-840-family radios through the Kenwood programming interface.

It is intentionally **read only**. It does not contain a radio write command.

The utility has been tested directly on the TK-840. The shared mask ROM also contains explicit support for the TK-940 and TK-941, but behavior on those models should still be verified against real hardware.

## Build

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk840download tk840download.c
```

## Named regions

```sh
./tk840download /dev/ttyUSB0 bootrom  bootrom.bin
./tk840download /dev/ttyUSB0 program  firmware.bin
./tk840download /dev/ttyUSB0 channels codeplug.bin
./tk840download /dev/ttyUSB0 ram      ram.bin
./tk840download /dev/ttyUSB0 sfr      sfr.bin
```

Aliases:

```text
rom / maskrom       -> bootrom
firmware / prog     -> program
channel / codeplug  -> channels
registers / regs    -> sfr
```

## Arbitrary address ranges

Start and end addresses are inclusive:

```sh
./tk840download /dev/ttyUSB0 0x0000 0x1fff bootrom.bin
./tk840download /dev/ttyUSB0 0x8000 0xe5ff firmware.bin
./tk840download /dev/ttyUSB0 0xe600 0xfdff codeplug.bin
```

The radio read protocol has only been verified using `0x80`-byte transactions.

For unaligned/manual ranges, the utility reads complete 128-byte blocks and saves only the requested bytes.

## Validate a saved image against the radio

`validate` performs a live read and compares it byte-for-byte with an existing file.

```sh
./tk840download /dev/ttyUSB0 validate bootrom bootrom.bin
./tk840download /dev/ttyUSB0 validate program firmware.bin
./tk840download /dev/ttyUSB0 validate channels codeplug.bin
```

Manual ranges are also supported:

```sh
./tk840download /dev/ttyUSB0 validate 0x8000 0xe5ff firmware.bin
```

Validation is read-only. It never writes the supplied file to the radio.

Exit status:

```text
0   successful dump or exact validation match
1   error
2   validation completed but the file differs from the radio
```

For a mismatch, the utility reports the first several differing CPU addresses and the total number of mismatched bytes.

## Memory map

| CPU range | Size | Purpose |
|---|---:|---|
| `0x0000-0x1FFF` | 8 KiB | Internal uPD78312A mask ROM |
| `0x2000-0x7FFF` | - | Apparently unmapped/open bus on tested TK-840 |
| `0x8000-0xE5FF` | `0x6600` / 26,112 bytes | Executable application firmware |
| `0xE600-0xFDFF` | `0x1800` / 6,144 bytes | Codeplug/channel/configuration data |
| `0xFE00-0xFEFF` | 256 bytes | Internal RAM |
| `0xFF00-0xFFFF` | 256 bytes | Special-function registers |

The external Flash is an `AT29C256` mapped beginning at `0x8000`.

The final 512 physical bytes of the Flash are not normally CPU-visible because internal RAM and SFRs occupy `0xFE00-0xFFFF`.

## Firmware checksums

When the selected range is exactly:

```text
0x8000-0xE5FF
```

the utility calculates:

- Kenwood 16-bit firmware checksum
- CRC-16/CCITT-FALSE
- SHA-256

The Kenwood checksum is the low 16 bits of the sum of every firmware byte:

```text
sum(bytes[0x8000..0xE5FF]) & 0xFFFF
```

It is a firmware identifier/checksum, not a cryptographic hash.

One recovered TK-840 firmware image produces:

```text
Kenwood checksum      8355
CRC-16/CCITT-FALSE    0368
SHA-256               7b061dc79ad69475484d68340edd872bd5e1a8f67efeb27bffbe3812a0ee7258
```

The resident firmware loader calculates the same 16-bit additive checksum after programming the executable Flash area.

## Programming protocol

The implemented read protocol was reconstructed from KPG-25D behavior and verified against a real TK-840.

### Enter PROGRAM mode

Initial serial parameters:

```text
1200 baud
8 data bits
no parity
2 stop bits
```

Sequence:

```text
PC -> radio   "PROGRAM"
radio -> PC   06              ACK

switch both sides to 9600 baud, 8N2

PC -> radio   02
radio -> PC   7-byte identification
PC -> radio   06              one-way ACK
```

Known model-identification strings constructed by the common mask ROM include:

```text
M890B1
M890B2
M890B3
M940B1
M941B1
```

The seventh identification byte indicates additional state such as password protection.

### Read transaction

Verified request:

```text
52 AH AL 80
```

where:

```text
52       ASCII 'R'
AH AL    16-bit big-endian CPU address
80       128-byte transfer length
```

The tested TK-840 responds with:

```text
06                    ACK
57 AH AL 80           'W' + address + length
<128 data bytes>
```

Some software layers may hide the initial ACK, so the utility accepts either the leading `0x06` or a response beginning directly with `W`.

After receiving the block:

```text
PC -> radio   06
radio -> PC   06
```

### Exit PROGRAM mode

```text
PC -> radio   "E"
```

A tested TK-840 may return no byte after `E`, so the utility does not require an ACK.

## Why normal writes cannot overwrite firmware

The ordinary KPG write transaction is:

```text
57 AH AL 80 <128 data bytes>
```

where `57` is ASCII `W`.

The resident PROGRAM monitor rejects normal writes below:

```text
0xE600
```

Therefore the normal codeplug-write path can modify the codeplug area but cannot overwrite executable firmware at `0x8000-0xE5FF`.

This protection is implemented in the radio's internal mask ROM, not merely in the PC software.

Firmware programming uses a separate resident loader.

## Safety

Although `tk840download` never sends the radio's write command, not every CPU address is necessarily safe to read.

Internal RAM is live working memory and may change while a dump is in progress.

Reading arbitrary SFRs in:

```text
0xFF00-0xFFFF
```

may have hardware side effects or access undefined registers.

The utility permits these reads for reverse-engineering work, but prints a warning.

Use arbitrary-range reads only when you understand what address space you are accessing.
