# Kenwood TK-840 / TK-940 / TK-941 Reverse Engineering

Reverse-engineering tools, firmware research, patches, and documentation for the Kenwood TK-840 family of commercial mobile radios.

The project currently focuses on the TK-840, TK-940, and TK-941, which share a common NEC 78K/III CPU and resident mask-ROM architecture.

## TK-941 ham-radio patches

Firmware patches are available for the **TK-941** to make it behave more like a normal amateur radio.

Most importantly, the patched firmware can be made to **honor the programmed TX frequency field**, instead of forcing the factory hard-coded repeater offset behavior. This makes the radio much more practical for amateur use and allows arbitrary transmit/receive frequency pairs where the hardware permits them.

Additional patches and firmware experiments are being developed as the firmware is reverse engineered.

## Tools

### `tk840download`

Read-only Linux/POSIX utility for dumping and validating radio memory.

It can read:

- internal mask ROM
- external application firmware
- codeplug/channel data
- arbitrary 16-bit CPU address ranges

It can also compare a saved image byte-for-byte against the live radio.

See **[tk840download README](README-tk840download.md)** for build instructions, commands, protocol details, checksums, and safety notes.

### Firmware programming / patching tools

The project also includes work on utilities for writing firmware, applying reversible firmware patches, and recovering radios through the resident loader.

Firmware writing is intentionally kept separate from the read-only downloader.

## Hardware architecture

The main CPU is an NEC:

```text
uPD78312AGF3563BE
```

The `uPD78312A` is part of NEC's 78K/III family and contains **8 KiB of internal mask ROM**.

The common mask ROM includes model support for:

```text
M890B1 / M890B2 / M890B3   TK-840 RF splits
M940B1                      TK-940
M941B1                      TK-941
```

The external program/configuration device is an `AT29C256` 32 KiB Flash ROM mapped beginning at CPU address `0x8000`.

Current memory map:

| CPU range | Purpose |
|---|---|
| `0x0000-0x1FFF` | Internal mask ROM |
| `0x2000-0x7FFF` | Apparently unmapped/open bus on tested TK-840 |
| `0x8000-0xE5FF` | Executable application firmware |
| `0xE600-0xFDFF` | Codeplug/channel/configuration data |
| `0xFE00-0xFEFF` | Internal RAM |
| `0xFF00-0xFFFF` | Special-function registers |

The front-panel CPU is a separate NEC `uPD75308BGK-740`, which handles the display and buttons and communicates with the main CPU.

## Resident mask ROM

The internal mask ROM is much more than a bootstrap.

It contains:

- reset/startup code
- hardware and model detection
- KPG PROGRAM-mode monitor
- CLONE mode
- firmware recovery/programming code
- AT29C256 page programming
- AT24C02 EEPROM access
- front-panel CPU serial-link support
- DAC and output-expander drivers
- arithmetic/BCD library routines
- a resident trampoline/API table at `0x1F00-0x1F4B`

The mask ROM appears to provide a common family-wide boot/service layer, while most model-specific operating behavior lives in external Flash.

## Firmware layout and recovery

Executable firmware occupies:

```text
0x8000-0xE5FF
```

The codeplug begins at:

```text
0xE600
```

The resident PROGRAM monitor prevents normal codeplug writes from overwriting executable firmware.

Firmware programming uses a separate loader in mask ROM. The loader writes the `AT29C256` in 64-byte pages and stops at `0xE600`, preserving the codeplug.

Because the firmware loader lives in internal mask ROM, the radio has a recovery path even when the external application firmware is missing or corrupt.

## Resident API / trampoline table

A stable trampoline table exists at:

```text
0x1F00-0x1F4B
```

It exposes resident routines for functions including:

- PROGRAM-mode entry
- EEPROM reads/writes
- DAC access
- output-expander control
- display/front-panel communication
- Flash programming
- CLONE mode
- model detection
- arithmetic/BCD helpers

Detailed calling conventions and reverse-engineering notes are maintained separately from this front-page overview.

## Project status

Confirmed on actual TK-840 hardware:

- PROGRAM-mode entry and radio identification
- arbitrary memory reads
- internal mask-ROM dump
- external firmware dump
- codeplug dump
- live-file validation
- firmware checksum calculation
- executable firmware and codeplug boundaries
- resident trampoline/API table

Work is also underway on:

- firmware upload and verification
- reversible firmware patching
- TK-941 ham-friendly behavior patches
- additional TK-940/TK-941 firmware analysis
- replacement/custom firmware

## Contributing

Useful contributions include:

- TK-840, TK-940, or TK-941 firmware and mask-ROM dumps
- additional firmware revisions
- confirmed firmware checksums
- disassembly annotations
- corrections to resident API calling conventions
- documentation of PROGRAM, CLONE, and recovery behavior
- testing of firmware patches on different radio revisions

When contributing binary dumps, please include the exact radio model, RF split, programming ID, firmware checksum, and SHA-256 digest.

## Warning

This is experimental reverse-engineering software for old commercial radio hardware.

Read-only tools are kept separate from write-capable utilities deliberately. Firmware patching or programming always carries some risk, so verify the exact radio model and firmware revision before writing anything.
