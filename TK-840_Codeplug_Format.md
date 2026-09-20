# Kenwood TK-840 Codeplug Format

## Reverse-engineered technical reference

**Document revision:** 2026-09-20  
**Status:** Experimental, substantially decoded for conventional operation  
**Verified radio firmware:** TK-840 firmware checksum `8355`  
**Codeplug size:** `0x1800` bytes (6144 bytes)  
**Radio CPU address range:** `0xE600-0xFDFF`  
**Primary evidence:** KPG-25D v3.x, TK-840 firmware 8355, TK-840 mask ROM, service documentation, and hardware testing on a real TK-840

This document describes the known format of the Kenwood TK-840 codeplug. The conventional channel format is now well understood and has been exercised on real hardware, including a 308-channel configuration. LTR structures and several commercial-only global options remain only partially decoded.

The word **proven** in this document means the behavior is supported by firmware/KPG analysis and, where practical, hardware testing. Findings involving unused bits apply specifically to the tested TK-840 firmware revision 8355 unless otherwise stated. Other firmware revisions may assign meaning to bits that firmware 8355 ignores.

### Terminology used in this document

This reference uses normal amateur-radio terminology wherever practical:

- **CTCSS (PL)** means analog subaudible tone squelch. Kenwood's QT terminology is not used.
- **DCS** means digital coded squelch. Kenwood's DQT terminology is not used.
- For conventional operation, this document normally says **channel** rather than Kenwood's **group** terminology. Exact KPG/menu labels are retained only when they help identify a factory option.


---

## 1. Addressing and file layout

The radio exposes the codeplug as exactly `0x1800` bytes at CPU addresses:

```text
CPU E600 -> image offset 0000
CPU E601 -> image offset 0001
...
CPU FDFF -> image offset 17FF
```

Conversion is therefore:

```text
CPU address = 0xE600 + image_offset
image_offset = CPU_address - 0xE600
```

A CHIRP `.img` file may be larger than `0x1800` bytes because CHIRP appends its own file metadata after the raw radio image. Only the first `0x1800` bytes are the TK-840 codeplug and are transferred to the radio.

### Top-level map

| Image offset | Size | Purpose | Status |
|---|---:|---|---|
| `0000-003F` | 64 | 32 System pointer words | Decoded |
| `0040` | 1 | Active System count | Decoded |
| `0041-0060` | 32 | Channel count for Systems 1-32 | Decoded |
| `0061-007F` | 31 | Global feature/options area | Partially decoded |
| `0080-00A7` | 40 | Repeater-information style table, likely LTR-related | Partially decoded |
| `00A8-00FF` | 88 | Reserved/unused in observed codeplug | Unmapped |
| `0100-17FF` | 5888 | Variable-length System blocks and channel records | Conventional format decoded |

The area from `0x0100` through `0x17FF` is a packed pool. System numbers do **not** imply fixed physical slots. Sparse System numbering is valid.

---

## 2. System pointer table: `0x0000-0x003F`

There are 32 little-endian 16-bit System pointer entries, one for each logical System number.

```text
System 1 pointer:  0000-0001
System 2 pointer:  0002-0003
...
System 32 pointer: 003E-003F
```

### Pointer word layout

```text
15            14            13                    0
+-------------+-------------+----------------------+
| unused flag | Sys enabled | encoded data pointer |
+-------------+-------------+----------------------+
```

| Bits | Meaning |
|---|---|
| 15 | `1` = System entry unused/unprogrammed; `0` = programmed |
| 14 | Conventional System Lockout state: `1` = System enabled/unlocked, `0` = locked out |
| 13-0 | Encoded pointer to the System block |

An unused pointer is normally `FFFF`.

### Pointer conversion

KPG-25D masks the two high flag bits before using the pointer:

```text
image_offset = (pointer & 0x3FFF) - 0x2600
```

Example:

```text
pointer = 0x6700
pointer & 0x3FFF = 0x2700
0x2700 - 0x2600 = 0x0100
```

Thus `0x6700` points to image offset `0x0100`, with bit 14 set, meaning the System is enabled for Fixed System Scan.

### System Lockout

Pointer bit 14 is a real System-level control and is separate from Scan List membership.

```text
bit 14 = 1 -> System enabled / not locked out
bit 14 = 0 -> System locked out
```

CHIRP maps this to its standard Skip field because System Lockout is the closest native meaning. Since lockout is System-wide, every channel in the same System necessarily shares the same Skip state.

Hardware testing also showed that the currently selected/revert System may still be scanned even when locked out, which is radio behavior rather than a codeplug inconsistency.

---

## 3. Active System count: `0x0040`

Byte `0x0040` contains the number of programmed System pointer entries.

This is a count of active Systems, not the highest System number. Sparse Systems are valid.

Example:

```text
Systems 1, 2, and 32 programmed -> 0x0040 = 3
```

The count must agree with the number of pointer-table entries whose bit 15 is clear.

---

## 4. Per-System channel counts: `0x0041-0x0060`

There are 32 one-byte counts, one for each System.

```text
System 1 count:  0041
System 2 count:  0042
...
System 32 count: 0060
```

A programmed conventional System stores the number of 19-byte channel records in its block. KPG-25D often calls these conventional channels "groups"; unused count entries are normally `FF`.

Documented Kenwood limits:

- 32 Systems maximum
- 250 conventional channels/groups maximum in one System
- 308 conventional channels total

The packed pool can impose a lower total when many Systems are active.

---

## 5. Packed System-data pool: `0x0100-0x17FF`

The System-data pool is `0x1700` bytes, or 5888 bytes.

A conventional System occupies:

```text
14-byte System header
+ N * 19-byte channel records
```

Thus the storage required for `S` active conventional Systems containing `C` total channels is:

```text
bytes = 14*S + 19*C
```

Subject to the documented 308-total and 250-per-System limits, the physical pool allows approximately:

```text
Cmax = floor((5888 - 14*S) / 19)
```

Examples:

| Active Systems | Physical channel capacity | Effective documented/layout limit |
|---:|---:|---:|
| 1 | 309 | 250 because of the per-System limit |
| 2 | 308 | 308 |
| 3 | 307 | 307 |
| 4 | 306 | 306 |
| 8 | 304 | 304 |
| 16 | 298 | 298 |
| 32 | 286 | 286 |

A real TK-840 has been hardware-tested successfully with **308 conventional channels split across two Systems**.

KPG-created codeplugs may leave large gaps or align Systems on convenient boundaries, but the pointer format does not require fixed slots. The CHIRP driver packs referenced blocks sequentially and leaves old unreferenced bytes alone rather than erasing the entire pool.

---

## 6. Conventional System header: 14 bytes

Each conventional System begins with a `0x0E`-byte header.

### Header layout

| Relative offset | Size | Meaning | Conventional status |
|---|---:|---|---|
| `+00` | 1 | System flags/type | Partially decoded |
| `+01` | 1 | Shared/LTR field | Not consumed by conventional firmware path |
| `+02` | 1 | Shared/LTR field | Not consumed by conventional firmware path |
| `+03` | 1 | Shared/LTR field | Not consumed by conventional firmware path |
| `+04` | 1 | Shared/LTR field | Not consumed by conventional firmware path |
| `+05` | 1 | Shared/LTR field | Not consumed by conventional firmware path |
| `+06-+0D` | 8 | System name | Decoded |

### Header byte `+00`

| Bit | Meaning |
|---:|---|
| 0 | System type: `0` = conventional, `1` = LTR |
| 1-3 | No consumer found in firmware 8355 conventional path |
| 4-6 | Used by LTR-side logic; not used by ordinary conventional path |
| 7 | Scan List exclusion, active-low: `0` = included, `1` = excluded |

### Scan List versus System Lockout

These are independent controls:

```text
System pointer bit 14 -> System Lockout / System Enabled
System header +00 bit 7 -> Scan List membership
```

For Scan List:

```text
header[0] bit 7 = 0 -> System is in Scan List
header[0] bit 7 = 1 -> System is not in Scan List
```

This active-low polarity was verified by firmware behavior.

### Header bytes `+01-+05`

Firmware tracing shows that the conventional code path skips these fields. Consumers found for these bytes are entered only for LTR Systems or shared-family behavior.

They should therefore be preserved rather than reinterpreted or normalized. Their lack of conventional use is proven for firmware 8355, but another firmware revision or related model could potentially use them differently.

A canonical/new conventional header currently used by the experimental CHIRP driver begins:

```text
FE FF FE FF FF FF
```

and then contains eight name bytes. Scan List membership and System Enabled state are applied separately.

### System name `+06-+0D`

The System name is eight display characters.

- Raw storage is ordinary single-byte ASCII-compatible data.
- `00` and `FF` are commonly used as fill/unused characters.
- The TK-840 front-panel display does not usefully render lower-case characters.
- The CHIRP driver therefore stores System names upper-case.

System names are shared by every channel in the System.

---

## 7. Conventional channel record: 19 bytes

Every conventional channel is a fixed `0x13`-byte record immediately following its System header.

### Record layout

| Relative offset | Size | Field |
|---|---:|---|
| `+00` | 1 | Channel number within System (Kenwood group number) |
| `+01-+02` | 2 | RX frequency word, little-endian |
| `+03-+04` | 2 | TX frequency word, little-endian |
| `+05-+06` | 2 | TX CTCSS/DCS word, little-endian |
| `+07-+08` | 2 | RX CTCSS/DCS word, little-endian |
| `+09` | 1 | Flags A |
| `+0A` | 1 | Flags B |
| `+0B-+12` | 8 | Channel name |

Channel numbers within an active System are sequential `1..N`.

---

## 8. Frequency words

RX and TX each use a little-endian 16-bit word.

### Numeric frequency coding

For ordinary TK-840 conventional operation:

```text
code = word & 0x7FFF
frequency_Hz = 300000000 + code * 12500
```

Equivalent MHz formula:

```text
frequency_MHz = 300.000 + code * 0.0125
```

The normal TK-840 therefore uses a fixed **12.5 kHz PLL raster**.

A hardware test conclusively demonstrated this: a code value that had previously been interpreted using an incorrect variable-grid theory caused the radio to transmit at the exact frequency predicted by the 12.5 kHz formula.

### No-frequency sentinel

If the lower 15 bits are `0x7FFF`, the frequency is absent/disabled.

Common representation:

```text
FFFF -> no frequency, high bit set
7FFF -> also numerically no frequency
```

For TX, this can represent transmit-off. An absent RX frequency makes the channel effectively empty.

### Bit 15

Bit 15 is **not part of the numeric frequency**.

Evidence:

- KPG-25D clears/masks bit 15 before doing frequency arithmetic.
- KPG-25D preserves bit 15 independently when editing an ordinary frequency.
- TK-840 firmware 8355 explicitly clears the high bit after fetching conventional RX or TX frequency words.
- No separate ordinary conventional-channel use of that bit has been found.
- KPG-created ordinary channel words observed on hardware have bit 15 set.

Current policy:

- Existing values are preserved by default.
- Newly created channels use bit 15 = `1`.
- Optional unused-bit normalization sets it to `1`.

**Important:** A separate Repeater Information structure appears to use bit 15 as a boolean/TEL-related field. That meaning must not be transferred to ordinary conventional channel frequency words merely because the storage type looks similar.

### Rounding

Because only 12.5 kHz points are representable, software should round entered values to the nearest grid point.

Examples:

```text
446.0100 MHz -> 446.0125 MHz
446.0110 MHz -> 446.0125 MHz
446.0040 MHz -> 446.0000 MHz
446.0190 MHz -> 446.0250 MHz
```

---

## 9. CTCSS (PL) and DCS words

CTCSS/DCS settings are stored as 16-bit little-endian words.

```text
record +05/+06 -> TX CTCSS/DCS
record +07/+08 -> RX CTCSS/DCS
```

This direction was verified on real hardware.

### No CTCSS/DCS

The driver recognizes these as no CTCSS or DCS:

```text
FFFF
7FFF
any word whose lower 15 bits are 7FFF
```

### CTCSS

CTCSS uses tag `0xC000`:

```text
word = 0xC000 | round(tone_Hz * 10)
```

Example conceptually:

```text
100.0 Hz -> 0xC000 | 1000
```

### DCS

DCS uses tag `0xE000` and a 12-bit payload.

For normal polarity:

- payload bit 0 is set
- each of the three octal digits is bit-reversed within a 3-bit field
- digit fields occupy bits 3-5, 6-8, and 9-11

Conceptually:

```text
payload = 1
payload |= reverse3(hundreds_digit) << 3
payload |= reverse3(tens_digit)     << 6
payload |= reverse3(ones_digit)     << 9
word = 0xE000 | payload
```

Reverse polarity is represented by complementing the 12-bit payload:

```text
payload ^= 0x0FFF
```

The service monitor may display multiple equivalent DCS representations because of the cyclic/inverted nature of the code; this does not imply multiple codes are programmed in the channel record.

---

## 10. Channel Flags A: record `+09`

All decoded feature bits in Flags A are **active-low**: `0` enables the feature, `1` disables it.

| Bit | Mask | Meaning | Ham-oriented status |
|---:|---:|---|---|
| 0 | `01` | Optional Signalling | Commercial/legacy |
| 1 | `02` | Talk Around | Commercial-style feature |
| 2 | `04` | TX Inhibit | Useful |
| 3 | `08` | Call | Commercial/legacy |
| 4 | `10` | Busy Channel Lockout (BCL) | Commercial/shared-channel feature |
| 5 | `20` | Horn | Commercial/legacy |
| 6 | `40` | Unused by firmware 8355 ordinary conventional path | Proven unused on tested firmware |
| 7 | `80` | Unused by firmware 8355 ordinary conventional path | Proven unused on tested firmware |

### TX Inhibit

TX Inhibit is independent of the stored TX frequency. This allows a valid transmit frequency to remain in the channel record while transmit is disabled.

This is why CHIRP's TK-840 driver does not treat TX Inhibit as identical to deleting the TX frequency.

### Talk Around

Talk Around causes transmission on the receive frequency rather than the programmed repeater transmit frequency. It is primarily a commercial-radio convenience feature; amateur users can usually represent the same intent more clearly with a separate simplex memory.

### Busy Channel Lockout

BCL inhibits transmit under busy-channel conditions according to the radio's commercial logic. With receive CTCSS or DCS programmed, it can prevent transmission when a carrier is present but the expected CTCSS/DCS does not match.

---

## 11. Channel Flags B: record `+0A`

| Bit | Mask | Meaning | Status |
|---:|---:|---|---|
| 0 | `01` | Data | Real firmware-consumed feature, exact behavior not fully decoded |
| 1-7 | `FE` | Unused by firmware 8355 ordinary conventional path | Proven unused on tested firmware |

The Data bit is active-low.

Firmware tracing shows that stored Flags B bit 0 is copied into a runtime flag position, proving that the radio does consume it. However, its exact audio/control behavior on the TK-840 has not yet been sufficiently mapped. It should therefore be treated as an advanced/commercial option, not assumed to mean generic amateur packet mode.

The existence of usable direct modulation/detector paths in the radio is a separate hardware fact and does not, by itself, prove the meaning of this per-channel Data flag.

---

## 12. Channel name: record `+0B-+12`

The channel name is eight characters.

Observed/KPG-supported character set includes:

```text
A-Z, a-z, 0-9
space
# $ % ( ) * + , - / = @ \ _ |
```

KPG's editor notably rejects `.` for this field.

Lower-case input may be accepted by software, but the TK-840 display does not render it properly. The experimental CHIRP driver stores names upper-case.

Unused trailing characters may be `00` or `FF`.

---

## 13. Global configuration area: `0x0061-0x007F`

This area contains KPG-25D Feature Option settings. The most useful fields have been mapped; several trunking/commercial fields remain unmapped at the byte/bit level.

### `0x0061` - TEL/interconnect time-out timer

High confidence mapping.

```text
raw 0..39 -> 15..600 seconds
seconds = (raw + 1) * 15
```

Kenwood's documented default is 180 seconds.

The observed codeplug contains `0x0B`, which decodes to 180 seconds.

The CHIRP ham-oriented driver currently does not expose this field because telephone/interconnect operation is not useful for normal amateur conventional operation.

### `0x0062` - Dispatch TX time-out timer

High confidence and exposed by CHIRP.

```text
raw 0..39 -> 15..600 seconds
seconds = (raw + 1) * 15
```

Kenwood's documented default is 60 seconds.

The observed codeplug contains `0x27`, which decodes to 600 seconds.

### `0x0063` - Scan drop-out / resume delay

Direct seconds:

```text
0..254 seconds
```

This is the delay after a received carrier/signal disappears before scanning resumes.

Kenwood's documented default is 3 seconds.

### `0x0064` - Post-TX dwell time

Direct seconds:

```text
0..254 seconds
```

This is the delay after transmission ends before scanning resumes.

Kenwood's documented default is 15 seconds.

### `0x0065` - Transpond delay

Commercial signalling feature. Strong KPG/storage correlation.

```text
0..254 seconds
```

It delays a transpond response after decoding a transpond-enabled ID. Kenwood documents a default of 3 seconds. If configured longer than the drop-out delay, the effective behavior may be limited by the drop-out delay.

Not exposed by the ham-oriented driver.

### `0x0066` - TX inhibit timer after inhibited ID

Commercial/trunking feature. Strong KPG/storage correlation.

Kenwood's UI range is:

```text
0.5 to 8.0 seconds in 0.5-second steps
```

The observed value `09` is consistent with 5.0 seconds if encoded as:

```text
seconds = (raw + 1) * 0.5
```

The exact firmware decode should be considered less thoroughly documented than the conventional channel fields.

### `0x0067` - AUX button assignment

Bits 0-2 select the front-panel AUX function:

| Value | Function |
|---:|---|
| 0 | Scan Add/Delete |
| 1 | Home Channel / Fixed Revert |
| 2 | Name / System-Channel Display |
| 3 | Auto-Tel / Telephone Search |
| 4 | Horn Alert |
| 5 | Manual Relay |
| 6 | Optional Signalling Reset |
| 7 | N/A |

Firmware 8355 has eight direct consumers of CPU address `E667`; every one masks the value with `07h` before use. Therefore bits 3-7 are proven unused by this firmware revision.

```text
bits 0-2 -> AUX assignment
bits 3-7 -> unused on firmware 8355
```

The optional Normalize Unused Bits policy sets bits 3-7 high.

### `0x0068` - Home / Fixed-Revert System

One-based System number, nominal range `1..32`.

Used by the AUX Home Channel / Fixed Revert function.

### `0x0069` - Home / Fixed-Revert Channel

One-based channel number within the selected System, nominal range `1..250`.

Used together with `0x0068` by the AUX Home Channel / Fixed Revert function.

### `0x006A` - Global scan/feature bitfield

Only the ham-relevant bits have been mapped confidently:

| Bit | Meaning |
|---:|---|
| 0 | `1` = Scan key/function N/A/disabled; `0` = scan enabled |
| 6 | When bit 0 is clear: `0` = Scan List mode, `1` = Fixed System Scan |

Thus:

```text
bit0=1                 -> N/A / Scan disabled
bit0=0 and bit6=0      -> Scan List
bit0=0 and bit6=1      -> Fixed System Scan
```

Other bits in this byte are consumed by firmware and correspond to KPG Feature Option behavior, but their exact mapping has not been fully documented here. KPG exposes nearby settings such as Revert System Type, Free System Ring Back, Clear To Talk, System Search, and Display Character. Most are trunking-oriented.

### `0x006B` - Off-hook and other feature flags

Bits 0-2 are proven active-low controls:

| Bit | Meaning | Polarity |
|---:|---|---|
| 0 | Off Hook Scan | `0` = enable, `1` = disable |
| 1 | Off Hook Horn Alert | `0` = enable, `1` = disable |
| 2 | Off Hook Decode | `0` = enable, `1` = disable |

Off Hook Scan is especially useful for amateur operation because it allows scanning to continue with the microphone removed from its hanger.

Off Hook Decode keeps CTCSS/DCS and optional-signalling decode active while off hook.

Firmware also consumes several higher bits in this byte. At least some correspond to additional KPG Feature Options such as external access/horn logic. They are not currently exposed by the ham-oriented driver and should be preserved.

### `0x006C-0x006F`

Part of the KPG Feature Option/global block. Not completely mapped.

KPG exposes global settings in this general feature block including:

- Revert System Type: Last Use / Last Call
- Free System Ring Back
- Clear To Talk
- System Search
- Display Character: Channel Name / System+Channel
- Minimum Volume
- Access Logic Signal
- Horn Alert Logic Signal
- Optional-signalling alert/transpond/decode/reset options

Not all of these have been assigned confidently to exact codeplug bytes/bits, so software should preserve these bytes unless a particular encoding has been proven.

### `0x0070` - CHIRP-private preferences, optional

`0x0070` is **not a native Kenwood field as currently understood**. Firmware 8355 contains no direct reference to CPU address `E670`, and the observed KPG-created codeplug stores `FF` there.

The experimental CHIRP driver can optionally use this byte for private policy metadata.

This use remains experimental because another TK-840 firmware revision could theoretically assign a meaning to this byte.

#### Metadata format

```text
FF       = no CHIRP metadata
F0-F7    = current 3-payload-bit format
F8-FE    = reserved
E0-EF    = future 4-payload-bit format
C0-DF    = future 5-payload-bit format
80-BF    = future 6-payload-bit format
00-7F    = future 7-payload-bit format
```

This is a variable-width prefix scheme. Preference bit meanings never move as the format expands.

Current payload bits:

| Bit | Meaning |
|---:|---|
| 0 | Normalize firmware-proven unused bits before upload |
| 1 | Disable commercial channel features before upload |
| 2 | Show commercial channel options in CHIRP |

A future driver that needs bit 3 can move from the `F0-F7` class to the `E0-EF` class without changing the meanings of bits 0-2.

Older drivers are expected to ignore unknown higher preference bits and preserve the existing prefix/unknown bits when modifying only preferences they understand.

If no metadata exists, the current ham-oriented defaults are:

```text
Normalize unused bits          = ON
Disable commercial features    = ON
Show commercial options        = OFF
```

When **Store CHIRP preferences in codeplug** is disabled, RC1 restores `0x0070` to `FF`. When it is enabled, only preference bits understood by that driver are changed; any future-format prefix and unknown preference bits are preserved.

### `0x0071-0x0079`

Observed as `FF` in the reference codeplug. Firmware 8355 has no direct literal references to CPU addresses `E671-E679`; preserve these bytes because indirect/table-driven use has not been ruled out.

### `0x007A`

Observed as `00` in the reference codeplug. Purpose unresolved. The non-`FF` value is a reason not to appropriate it for private metadata without further tracing.

### `0x007B-0x007C`

Likely related to KPG's Data System/Group feature (effectively Data System/Channel for conventional operation), but the exact encoding and firmware semantics are not sufficiently proven for this document.

### `0x007D-0x007F`

Observed as `FF` in the reference codeplug. Firmware 8355 has no direct literal references to CPU addresses `E67D-E67F`; preserve these bytes because indirect/table-driven use has not been ruled out.

---

## 14. Repeater Information / frequency-pair table: `0x0080-0x00A7`

This area is live data, not merely filler.

The application firmware contains repeated references to CPU address `E680`, which corresponds to image offset `0x0080`. Multiple routines use arithmetic equivalent to:

```text
entry_address = 0xE680 + ((index - 1) * 4)
```

This establishes an array of 4-byte records.

The observed codeplug contains seven populated records:

| Image offset | Word 1 | Word 2 | Decoded pair on TK-840 frequency formula |
|---|---:|---:|---|
| `0080` | `AEE8` | `AEE0` | 450.100 / 450.000 MHz |
| `0084` | `AF10` | `AF08` | 450.600 / 450.500 MHz |
| `0088` | `B4B0` | `B4A8` | 468.600 / 468.500 MHz |
| `008C` | `B4D8` | `B4D0` | 469.100 / 469.000 MHz |
| `0090` | `B548` | `B4F8` | 470.500 / 469.500 MHz |
| `0094` | `BA98` | `BA90` | 487.500 / 487.400 MHz |
| `0098` | `BAB6` | `BAB8` | 487.875 / 487.900 MHz |

Bytes from `0x009C` onward are `FF` in the observed radio.

Firmware initialization copies/repairs a `0x28`-byte area starting at `E680`, which is consistent with storage for up to ten 4-byte entries, although only seven are populated in the observed codeplug.

KPG-25D contains a **Repeater Information** screen with Receive, Transmit and TEL fields, and the structure is strongly consistent with this table. The exact linkage and all bit semantics are not considered fully proven yet.

This table is probably associated with LTR repeater definitions and is not required for ordinary amateur conventional operation.

**Do not assume the high-bit semantics of these Repeater Information words are the same as ordinary conventional channel frequency words.** KPG has separate logic for this structure.

---

## 15. Remaining `0x00A8-0x00FF`

This range is `FF` in the observed codeplug and has not yielded a ham-useful decoded function.

It should be preserved rather than repurposed unless firmware/KPG analysis proves a byte unused across the intended firmware range.

---

## 16. Scan behavior summary

The TK-840 has several related but distinct scan concepts.

### Global Scan Switch: `0x006A`

Selects:

- N/A / disabled
- Scan List
- Fixed System Scan

### System Lockout: pointer bit 14

Controls whether the System is enabled for Fixed System Scan.

### Scan List: System header `+00` bit 7

Controls whether the System participates in Scan List mode.

### AUX Scan Add/Delete

The AUX key can temporarily add/delete a System from scan. This behaves as a runtime/nuisance-delete style function and should not be confused with permanently changing every channel record.

### Off Hook Scan: `0x006B` bit 0

Controls whether taking the microphone off hook stops scanning. For typical amateur use, enabling Off Hook Scan is usually desirable.

---

## 17. New conventional System construction

Because the conventional header is now sufficiently understood, a newly created System does not need to inherit opaque bytes from an unrelated System.

A clean KPG-style conventional header can be initialized from:

```text
FE FF FE FF FF FF FF FF FF FF FF FF FF FF
```

then modified as follows:

- clear header byte 0 bit 0 for conventional mode, already clear in `FE`
- set/clear header byte 0 bit 7 according to Scan List membership
- store the eight-character System name at `+06-+0D`
- set pointer bit 14 according to System Enabled/Lockout state

The experimental CHIRP driver defaults a newly activated System to:

```text
System Enabled = yes
Scan List      = yes
System Name    = blank
```

Unused Systems have no pointer/header on the radio. CHIRP may temporarily hold settings for an unused System in the current editing session, but those settings cannot persist in the native codeplug until at least one channel is assigned to that System.

---

## 18. Newly created conventional channel defaults

For a genuinely new channel record, the ham-oriented driver uses conservative defaults:

- optional/commercial active-low flags set high, meaning disabled
- TX Inhibit controlled independently
- Flags A bits 6-7 set high
- Flags B bits 1-7 set high
- RX/TX frequency bit 15 set high
- channel number rewritten according to position within the destination System

When CHIRP is shifting/copying an existing row, raw hidden flags and frequency high bits are preserved so that a row insertion does not silently normalize unknown state.

---

## 19. Firmware-proven unused bits and normalization

For firmware 8355, the following stored bits are proven unused by ordinary conventional operation:

```text
Channel Flags A bits 6-7
Channel Flags B bits 1-7
RX frequency word bit 15
TX frequency word bit 15
Global AUX byte 0x0067 bits 3-7
```

The CHIRP driver's **Normalize unused bits** policy sets these to `1` before upload.

This policy is intentionally firmware-specific. A different TK-840 firmware revision could theoretically use one of these bits. That is one reason the driver should remain marked experimental until broader firmware coverage exists.

---

## 20. Commercial-feature cleanup policy

The ham-oriented CHIRP driver can optionally force these active-low features to their disabled (`1`) state on every conventional channel before upload:

```text
Optional Signalling
Talk Around
Call
Busy Channel Lockout
Horn
Data
```

TX Inhibit is deliberately **not** included because it is independently useful for receive-only amateur memories.

This is a CHIRP policy, not a special native codeplug field.

---

## 21. LTR Systems

An active System is identified as LTR when System header byte `+00` bit 0 is set.

The TK-840 clearly supports mixed trunked/conventional operation, and KPG-25D has a much larger LTR System/group feature set. The LTR block structure has not been mapped to the same confidence level as conventional mode.

Current safe rule:

- conventional Systems can be structurally edited/repacked
- active LTR Systems should be treated as opaque
- the experimental CHIRP driver refuses variable structural editing on a codeplug containing active LTR Systems

Known KPG LTR-only or primarily trunking-oriented features include Scan Weight, Auto Telephone Search, fixed IDs, block ID ranges, System Search, Free System Ring Back, Clear To Talk and Repeater Information.

---

## 22. Radio programming context

This section is included for implementers but is not part of the codeplug's internal data format.

The raw codeplug occupies CPU addresses:

```text
E600-FDFF
```

The verified programming handshake is:

```text
1. 1200 baud: send "PROGRAM"
2. radio ACKs
3. switch to 9600 baud, 8 data bits, no parity, 2 stop bits
4. send 02h
5. radio returns 7-byte identification, e.g. M890B1N
6. ACK and continue clone transactions
```

When leaving PROGRAM mode, the final `E` command has been observed to return no byte on real TK-840 hardware; software should not require a final ACK.

Codeplug reads/writes use `0x80`-byte blocks. The experimental CHIRP uploader:

1. enters PROGRAM mode once
2. reads the live `0x1800`-byte image
3. writes only changed `0x80`-byte blocks
4. reads the entire image back
5. requires byte-for-byte verification
6. exits PROGRAM mode

The application firmware occupies `0x8000-0xE5FF`; the codeplug begins immediately after it at `0xE600`.

---

## 23. Related-model implications

The TK-840, TK-940 and TK-941 share KPG-25D and a common mask-ROM family layer. The mask ROM explicitly contains model-identification paths for:

```text
M890B1 / M890B2 / M890B3   TK-840 family RF splits
M940B1                      TK-940
M941B1                      TK-941
```

This strongly suggests that much of the codeplug framework is shared across the family. The System pointer/count/header/channel layout may prove nearly identical on the 940/941, with likely model-specific differences in frequency coding, valid ranges, and some global options.

This has not yet been hardware-verified on TK-940/TK-941 and should not be treated as supported behavior without comparison dumps.

---

## 24. Confidence summary

### Very high confidence / hardware and firmware supported

- raw codeplug size and address range
- pointer table and pointer conversion
- pointer bit 15 unused-entry flag
- pointer bit 14 System Lockout/System Enabled
- active System count
- per-System channel counts
- variable-length packed conventional System blocks
- 14-byte conventional System header size
- System type bit
- Scan List bit and polarity
- 8-byte System name
- 19-byte conventional record layout
- RX/TX frequency locations and 12.5 kHz encoding
- TX/RX CTCSS/DCS word locations
- CTCSS/DCS encoding used by the driver
- Flags A feature mapping
- Flags B Data bit and unused upper bits on firmware 8355
- AUX bits 0-2 and unused bits 3-7 on firmware 8355
- Scan Switch bit 0 / bit 6 behavior
- Off Hook Scan/Decode/Horn bits
- Dispatch TOT, scan drop-out and dwell locations/encoding
- Home/Fixed-Revert System and Channel locations
- sparse System numbering
- 308-channel operation with two Systems

### High confidence, but less central to conventional ham use

- TEL TOT at `0x0061`
- Transpond delay at `0x0065`
- TX inhibit timer at `0x0066`
- existence and 4-byte indexing of the `0x0080` table

### Partial / intentionally not fully decoded

- exact mapping of every bit in `0x006A-0x006F`
- Data System/Group storage
- full Repeater Information/TEL semantics
- LTR System/group block format
- exact purpose of `0x007A`
- all bytes from `0x00A8-0x00FF`

### CHIRP-private / not Kenwood-native

- optional preference metadata at `0x0070`

---

## 25. Reference codeplug global bytes

One real KPG/CHIRP-derived TK-840 image contained:

```text
0060: FF 0B 27 03 0F 03 09 FF 01 01 7D EF F0 FE 1E 08
0070: FF FF FF FF FF FF FF FF FF FF 00 FF FF FF FF FF
0080: E8 AE E0 AE 10 AF 08 AF B0 B4 A8 B4 D8 B4 D0 B4
0090: 48 B5 F8 B4 98 BA 90 BA B6 BA B8 BA FF FF FF FF
00A0: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
...
00F0: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
```

Do not treat this byte pattern as a universal default. It is included as a useful comparison sample.

---

## 26. Evidence used for this map

This format was reconstructed from several independent sources:

1. **Kenwood KPG-25D v3.x** static reverse engineering, including its pointer arithmetic, UI strings, bit tests and frequency-edit routines.
2. **TK-840 external firmware revision/checksum 8355** static analysis, including consumers of conventional records and global bytes.
3. **TK-840 mask ROM** analysis, used primarily for programming/service behavior and family identification.
4. **Real TK-840 hardware testing**, including clone read/write, frequency/CTCSS/DCS behavior, scanning, System moves, sparse Systems and a 308-channel two-System image.
5. **Kenwood TK-840 service documentation**, used to correlate firmware/KPG fields with named radio features and documented value ranges/defaults.

Where these sources disagree or where only one source supports an interpretation, this document deliberately labels the field partial/uncertain instead of presenting speculation as fact.

---

## 27. Open reverse-engineering items

The conventional format is sufficiently decoded for normal amateur use, but these areas remain worthwhile future work:

- compare codeplugs from additional TK-840 firmware revisions
- confirm whether firmware revisions other than 8355 ignore the same unused bits and `0x0070`
- fully map remaining Feature Option bits around `0x006A-0x006F`
- locate Minimum Volume and Display Character precisely
- completely decode Data System/Group and the per-channel Data feature's signal-path effects
- fully decode Repeater Information at `0x0080`
- map LTR System/group structures
- compare TK-940 and TK-941 codeplugs to determine how much of this layout is shared

Until broader firmware testing is available, software based on this map should retain an **experimental** designation and preserve unknown fields wherever possible.
