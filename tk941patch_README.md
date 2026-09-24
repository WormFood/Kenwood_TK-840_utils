# tk941patch v5

`tk941patch` is a data-driven firmware patcher for the Kenwood TK-941. The built-in firmware modifications are TK-941-specific, while external `.tkpatch` files can also be used for controlled bench tests such as the TK-840 restoration test.

It can patch a raw `0x6600`-byte firmware image offline or patch a connected radio. Live writes force and verify the firmware-recovery enable bit, write only changed 64-byte AT29C256 pages, and verify the complete firmware afterward.

## Build

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk941patch tk941patch.c
```

## Interactive patch-file UI

A positional filename ending in `.tkpatch` is now loaded automatically. You do not have to specify the internal patch name.

For example:

```sh
./tk941patch --dry-run radio /dev/ttyUSB0 tk840_restore_motorola.tkpatch
```

After the firmware is read, `tk941patch` tests every loaded patch definition against the untouched firmware and shows every unambiguous action it can perform. An unapplied definition is shown as **APPLY**; if all replacement bytes are already present, the same definition is shown as **REVERT**:

```text
Patch actions available for this firmware:
  1) APPLY  tk840-restore-motorola  [known SHA-256]
     TK-840 8355 test: restore "HEY! Dave fixed your shit!" to factory "HEY!  MOTOROLA "
Select action [1] (Enter=1, q=quit):
```

If that patch is already present, the same menu item becomes:

```text
  1) REVERT tk840-restore-motorola  [patch bytes already present]
```

Selecting **REVERT** writes the exact original bytes from the left side of each `replace old -> new` definition.

With several applicable patches, enter a list such as `1,3`, or `a` for all. Explicit patch names are still accepted for scripts and non-interactive use.

The older `--patch-file FILE` option also remains supported. If no explicit patch names are supplied, the same interactive menu is shown after the firmware is read.

If an external patch file duplicates a built-in definition, the menu suppresses the duplicate and shows the externally loaded patch name.

## Reversing patches

Patch definitions are inherently reversible because every hunk contains both the exact original and replacement bytes. v5 determines the action from the untouched source firmware:

- all hunks contain the original bytes: **APPLY**;
- all hunks contain the replacement bytes: **REVERT**;
- a mixture of original and replacement hunks: report a partial/mixed state and refuse to guess.

For reversal at a patch's declared CPU address, exact replacement bytes are sufficient even if another loaded patch changed nearby context. This is needed, for example, when reverting the TK-941 25 MHz patch while the TX-field patch remains installed. Relocated matches still require exact surrounding context; the relaxation is only for reversing exact replacement bytes at the definition's recorded address.

Selecting multiple menu items performs the action shown for each item. Thus if one patch is installed and another is not, `a` can intentionally revert the first while applying the second.

## Patch identity and matching

A known revision can specify both Kenwood's 16-bit additive checksum and SHA-256. SHA-256 is the strongest identity check.

Matching is deliberately conservative:

1. Known SHA-256 plus exact expected bytes/context at the recorded CPU address.
2. If the SHA-256 differs, search for the exact old/new patch bytes plus exact `before` and `after` context. A match must resolve unambiguously.
3. `--relaxed-identity` permits a unique exact-byte-only fallback when context cannot be matched. This is intentionally not the default.
4. Ambiguous matches are refused.

All matching is resolved against the untouched source image before any selected patch is applied, so one patch cannot invalidate another patch's context checks.

## Patch files

Format:

```text
[patch b5ec-txfield]
description = TK-941 B5EC: use stored channel TX-frequency word directly
model = M941B1
sum16 = B5EC
sha256 = 1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818
replace 0x9C6E : 28 9D 9C 71 9E 0A 2D F0 09 1A 20 3A 22 01 14 18 -> 28 9A DE 83 29 60 03 00 88 E8 59 24 01 5D 03 9F
before = 00 28 59 9B 28 46 9D 56
after = 08 A0 DA 05 2D E0 FB 14
```

CPU addresses are used, not file offsets. `before` and `after` belong to the immediately preceding `replace` line and are exact byte sequences. There are no wildcards.

## Learning a new firmware revision

If a patch safely relocates by exact contextual matching, `--learn FILE` writes a revision-specific patch-definition file containing the actual source SHA-256, sum16, resolved CPU addresses, and fresh eight-byte contexts:

```sh
./tk941patch --model M941B1 --learn new-revision.tkpatch --dry-run \
    file unknown.bin unused.bin tk941patches.tkpatch
```

Choose the applicable patch from the menu. The learned file is created with exclusive-create semantics and will not overwrite an existing file.

## Built-in patches

### `tk941-txfield-b5ec`

Preferred TK-941 B5EC ham patch. Replaces the 16-byte conventional TX routine at CPU `0x9C6E` so the radio uses the TX-frequency word stored in the channel record rather than deriving TX from the RX frequency and stock fixed split.

Known source:

```text
sum16    B5EC
SHA-256  1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818
```

Known TX-field-only patched result:

```text
sum16    B725
SHA-256  9f33d61bbda7902f6930768732a87fdada5ef4b8f0f20744266dde5dd0c84fed
```

### `tk941-25mhz-b5ec`

Changes the three known B5EC fixed-split calculations from 39 MHz to 25 MHz. When the TX-field patch is active, normal conventional TX uses the stored TX field and bypasses the fixed-split branch in that path.

## Typical commands

Interactive live-radio use with a patch file:

```sh
./tk941patch --dry-run radio /dev/ttyUSB0 tk941patches.tkpatch
./tk941patch radio /dev/ttyUSB0 tk941patches.tkpatch
```

TK-840 bench-test restoration:

```sh
./tk941patch --dry-run radio /dev/ttyUSB0 tk840_restore_motorola.tkpatch
./tk941patch radio /dev/ttyUSB0 tk840_restore_motorola.tkpatch
```

Non-interactive/scripted use remains available:

```sh
./tk941patch --patch-file tk941patches.tkpatch \
    radio /dev/ttyUSB0 b5ec-txfield
```

Offline use also supports the menu:

```sh
./tk941patch --model M941B1 \
    file TK-941_firmware.bin TK-941_ham.bin tk941patches.tkpatch
```


## Friendly `--model` names

For unknown firmware revisions, `--model` accepts `840`, `940`, or `941`, with optional `TK` prefixes/separators, plus exact internal IDs such as `M941B1`. Examples: `tk840`, `tk-840`, `TK 840`, `TK-840-1`, `tk941`, `tk-941`, and `M941B1`. TK-840 B1/B2/B3 forms are accepted. 890 is not a user-facing model alias.
