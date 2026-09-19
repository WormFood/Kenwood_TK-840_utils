# Kenwood TK-840 Family Reverse Engineering Tools

Reverse-engineering notes and utilities for the Kenwood TK-840 family of commercial mobile radios, centered on the TK-840 and its shared CPU/firmware architecture with the TK-940 and TK-941.

The current utility, `tk840dump`, is intentionally **read only**. It can dump named memory regions or arbitrary 16-bit address ranges through the radio's programming interface and can compare a saved image byte-for-byte against the live radio.

The project also documents the main CPU's internal mask ROM, the external Flash layout, the programming protocol, the resident firmware-loader, and the mask-ROM trampoline/API table at `0x1F00-0x1F4B`.

## Hardware architecture

### Main CPU

The radio uses an NEC:

```text
uPD78312AGF3563BE
```

The `uPD78312A` is a member of NEC's 78K/III family. In this radio it contains **8 KiB of internal mask ROM**.

The `3563` mask-ROM code appears to be shared across the radio family. The mask ROM contains explicit hardware-detection and model-identification support for:

```text
M890B1 / M890B2 / M890B3   TK-840 RF splits
M940B1                      TK-940
M941B1                      TK-941
```

The TK-840 has been tested directly. TK-940/TK-941 behavior is inferred from the decoded common mask ROM and Kenwood documentation until dumps from those radios are compared.

### External Flash

The main nonvolatile program/configuration device is an:

```text
AT29C256
```

This is a 32 KiB Flash device physically mapped beginning at CPU address `0x8000`.

The useful CPU-visible portions are:

| CPU range | Size | Purpose |
|---|---:|---|
| `0x8000-0xE5FF` | `0x6600` / 26,112 bytes | Executable application firmware |
| `0xE600-0xFDFF` | `0x1800` / 6,144 bytes | Codeplug/channel/configuration data |
| `0xFE00-0xFEFF` | 256 bytes | CPU internal RAM shadows Flash |
| `0xFF00-0xFFFF` | 256 bytes | CPU SFR space shadows Flash |

The last 512 physical bytes of the AT29C256 are therefore not normally visible through the CPU address map because internal RAM and SFRs occupy `0xFE00-0xFFFF`.

### Internal mask ROM

```text
0x0000-0x1FFF   8 KiB internal mask ROM
```

The mask ROM is not merely a bootstrap stub. It contains:

- reset/startup code
- hardware/model detection
- PROGRAM-mode monitor
- CLONE mode
- firmware recovery/programming code
- AT29C256 page-programming primitives
- AT24C02 EEPROM access
- front-panel CPU serial-link support
- DAC and output-expander drivers
- arithmetic/BCD library routines
- a stable resident trampoline/API table at `0x1F00-0x1F4B`

The current known mask-ROM dump has SHA-256:

```text
0572a52ad964ff67afc25feb0dbde5e7ad279cc5d00c47cc5ba1f9b2ae242543
```

### Other hardware exposed by the resident ROM

The decoded mask-ROM API also directly supports:

- `AT24C02` serial EEPROM
- `M62363FP` 8-channel DAC
- `BU4094/XRU4094` output shift register
- the front-panel/display CPU serial link

The front-panel CPU is a separate NEC `uPD75308BGK-740`. It handles the display/buttons and communicates with the main `uPD78312A`.

## CPU memory map

The currently understood address map is:

```text
0000-1FFF   Internal uPD78312A mask ROM
2000-7FFF   Apparently unmapped/open bus on the tested TK-840
8000-E5FF   External executable firmware
E600-FDFF   Codeplug/channel/configuration data
FE00-FEFF   Internal RAM
FF00-FFFF   Special-function registers
```

### Warning about RAM and SFR reads

`tk840dump` is read-only at the Kenwood programming-protocol level, but not every CPU address is necessarily safe to read.

Internal RAM is live working memory and may change while a dump is in progress.

Reading arbitrary SFRs in `0xFF00-0xFFFF` may have hardware side effects, access undefined registers, or otherwise affect radio operation. The program intentionally permits these reads for reverse-engineering work, but prints a warning.

## `tk840dump`

`tk840dump` is a Linux/POSIX command-line utility for reading the radio through the Kenwood programming interface.

It **does not contain a radio write command**.

### Build

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk840dump tk840dump.c
```

### Named regions

```sh
./tk840dump /dev/ttyUSB0 bootrom  bootrom.bin
./tk840dump /dev/ttyUSB0 program  firmware.bin
./tk840dump /dev/ttyUSB0 channels codeplug.bin
./tk840dump /dev/ttyUSB0 ram      ram.bin
./tk840dump /dev/ttyUSB0 sfr      sfr.bin
```

Aliases are also accepted:

```text
rom / maskrom       -> bootrom
firmware / prog     -> program
channel / codeplug  -> channels
registers / regs    -> sfr
```

### Arbitrary address ranges

Start and end addresses are inclusive:

```sh
./tk840dump /dev/ttyUSB0 0x0000 0x1fff bootrom.bin
./tk840dump /dev/ttyUSB0 0x8000 0xe5ff firmware.bin
./tk840dump /dev/ttyUSB0 0xe600 0xfdff codeplug.bin
```

The radio read protocol has only been verified using `0x80`-byte transactions. For an unaligned/manual range, the utility reads complete 128-byte blocks and saves only the requested bytes.

### Validate a saved image against the radio

`validate` performs a complete live read and compares it byte-for-byte with an existing file.

```sh
./tk840dump /dev/ttyUSB0 validate bootrom bootrom.bin
./tk840dump /dev/ttyUSB0 validate program firmware.bin
./tk840dump /dev/ttyUSB0 validate channels codeplug.bin
```

Manual ranges are also supported:

```sh
./tk840dump /dev/ttyUSB0 validate 0x8000 0xe5ff firmware.bin
```

Validation is also read-only. It never writes the supplied file to the radio.

Exit status:

```text
0   successful dump or exact validation match
1   error
2   validation completed but the file differs from the radio
```

For a mismatch, the utility reports the first several differing CPU addresses and the total number of mismatched bytes.

## Firmware checksums

When the selected range is exactly:

```text
0x8000-0xE5FF
```

the utility calculates and displays:

- Kenwood 16-bit firmware checksum
- CRC-16/CCITT-FALSE
- SHA-256

The Kenwood value is simply the low 16 bits of the sum of every firmware byte:

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

The mask-ROM firmware loader itself calculates the same 16-bit additive checksum after programming the executable Flash area.

## Programming protocol

The currently implemented read protocol was reconstructed from KPG-25D behavior and verified against a real TK-840.

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

The seventh byte used on the programming interface indicates additional state such as password protection.

### Read transaction

The verified read request is:

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

## Normal codeplug writes

Although `tk840dump` does not write, the normal KPG programming monitor has also been reverse engineered.

A normal write transaction uses:

```text
57 AH AL 80 <128 data bytes>
```

where `57` is ASCII `W`.

The resident PROGRAM monitor explicitly rejects normal writes below:

```text
0xE600
```

Therefore the ordinary KPG channel/programming write path can modify the codeplug area but cannot overwrite executable firmware at `0x8000-0xE5FF`.

This protection is in the radio's mask ROM, not merely in the PC software.

## Firmware programming and recovery

Executable firmware uses a separate programming path from normal codeplug writes.

The mask ROM contains a complete resident firmware loader, allowing recovery even when the external application firmware is missing or corrupt.

The external executable region is exactly:

```text
0x8000-0xE5FF
size = 0x6600 bytes
```

The loader programs the AT29C256 in its native **64-byte pages**.

The recovered binary loader structure is approximately:

```text
wait for firmware-loader synchronization

destination = 0x8000

repeat until 0xE600:
    receive 64 bytes
    program one AT29C256 page

    receive 64 bytes
    program one AT29C256 page
```

The mask ROM contains the AT29C256 protected-page sequence:

```text
AA -> D555
55 -> AAAA
A0 -> D555
<64 data bytes>
```

Because the Flash begins at CPU address `0x8000`:

```text
AT29C256 chip address 5555 -> CPU D555
AT29C256 chip address 2AAA -> CPU AAAA
```

The generic resident page writer is exposed through trampoline `0x1F48`.

The firmware loader stops at `0xE600`, preserving the codeplug area.

The mask ROM also contains recovery logic that checks the external program image during boot. If the expected external firmware identification is missing/corrupt, it can remain in resident programming/recovery code rather than depending on the damaged Flash application.

## Mask-ROM resident API / trampoline table

Near the end of the 8 KiB mask ROM is a table of 3-byte absolute branch trampolines:

```text
0x1F00-0x1F4B
```

Application firmware can call the stable trampoline address without depending on the actual location of the resident implementation.

The current table is:

| Entry | Target | Function |
|---|---:|---|
| `1F00` | `0D34` | KPG PROGRAM monitor entry, non-returning |
| `1F03` | `1604` | 16-bit binary to 4-digit packed BCD |
| `1F06` | `1675` | Signed packed-BCD addition |
| `1F09` | `1666` | Signed packed-BCD subtraction |
| `1F0C` | `010C` | Clear resident working RAM |
| `1F0F` | `00ED` | Baseline port/GPIO initialization |
| `1F12` | `0116` | Interrupt-controller baseline initialization |
| `1F15` | `020F` | Radio family/RF-split hardware detection |
| `1F18` | `0773` | AT24C02 multi-byte/page write |
| `1F1B` | `071A` | AT24C02 random single-byte read |
| `1F1E` | `075B` | AT24C02 single-byte write |
| `1F21` | `0729` | AT24C02 sequential multi-byte read |
| `1F24` | `06BE` | M62363FP 8-channel DAC write |
| `1F27` | `06F4` | BU4094/XRU4094 output-expander update |
| `1F2A` | `170A` | Display-link receive/start recovery |
| `1F2D` | `1714` | Queue/start display-link transmit byte |
| `1F30` | `17A3` | INTE0/display-link start ISR |
| `1F33` | `1726` | CRF11/display-link bit-state ISR |
| `1F36` | `1113` | Fixed 64-byte Flash write |
| `1F39` | `118D` | Resident CLONE-mode program, non-returning |
| `1F3C` | `1161` | AT29C256 software-data-protection disable |
| `1F3F` | `114E` | AT29C256 protected page-program prefix |
| `1F42` | `0877` | Cooperative AT24C02 single-byte write |
| `1F45` | `0838` | Cooperative AT24C02 random byte read |
| `1F48` | `1129` | Generic 64-byte AT29C256 page writer |
| `1F4B` | `1089` | Build radio model-identification field |

The detailed trampoline documentation contains calling conventions, register and RAM parameters, outputs, clobbers, hardware side effects, known firmware callers, and caveats for replacement-firmware use.

One particularly important ABI detail is that the cooperative EEPROM routines at `1F42` and `1F45` call external application address:

```text
0x8235
```

as a background-service hook. Replacement firmware using those resident routines must provide a valid callable routine at that address.

## Shared-family architecture

The decoded mask ROM is clearly intended to support more than one RF model.

The hardware-detection routine at `1F15` reads analog strap inputs and produces model-selection flags. The model-string routine at `1F4B` converts those flags into:

```text
M940B1
M941B1
M890B1
M890B2
M890B3
```

This is strong evidence that the common mask ROM was designed as a family-wide boot/service layer while model-specific operating behavior lives primarily in external Flash.

Obtaining and comparing TK-940 and TK-941 mask-ROM and firmware dumps is a planned next step.

## Project status

Confirmed on actual TK-840 hardware:

- PROGRAM-mode entry
- radio identification
- arbitrary `0x80`-byte memory reads
- mask-ROM dump
- external firmware dump
- codeplug dump
- live-file validation
- firmware checksum calculation
- `0x0000-0x1FFF` mask-ROM structure
- `0x8000-0xE5FF` executable firmware boundary
- `0xE600-0xFDFF` codeplug boundary
- complete `0x1F00-0x1F4B` trampoline table

Reverse engineered but not implemented in the current read-only utility:

- ordinary codeplug writes
- executable firmware programming
- CLONE mode
- replacement/custom application firmware

## Safety and scope

This project is experimental reverse-engineering software.

`tk840dump` is intentionally read-only and does not send the radio's `W` command. A separate write-capable utility may be developed later rather than weakening the safety properties of the reader.

Even with a read-only protocol, arbitrary CPU reads are not necessarily harmless. In particular, SFR reads may cause hardware side effects.

Use the tools with an understanding of the radio, its programming interface, and the risks of accessing undocumented address space.

## Contributions

Useful contributions include:

- TK-940/TK-941 dumps made with the read-only utility
- mask-ROM comparisons
- additional firmware revisions
- confirmed Kenwood firmware checksums
- disassembly annotations
- corrections to trampoline calling conventions
- documentation of programming/clone behavior

When contributing binary dumps, include the exact radio model, RF split, programming ID, firmware checksum, and a SHA-256 digest.
