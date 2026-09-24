/*
 * tk840upload.c - Companion writer for tk840dump.
 *
 * Linux/POSIX utility for Kenwood TK-840-family radios.
 *
 * Supported images:
 *   codeplug  E600-FDFF  0x1800 bytes
 *   firmware  8000-E5FF  0x6600 bytes
 *
 * Safety policy:
 *   - Read the live radio first and write only changed blocks/pages.
 *   - Codeplug writes use the verified 0x80-byte PROGRAM-mode W transaction.
 *   - Every codeplug block is immediately read back, followed by a full-image
 *     byte-for-byte verification.
 *   - Firmware diffs are calculated in the AT29C256 native 64-byte page size.
 *   - Before firmware programming, codeplug E66C bit 2 is forced ON and
 *     verified, unless --force-unsafe is explicitly supplied.
 *   - Codeplug uploads also force E66C bit 2 ON by default.  --force-unsafe
 *     permits an exact image to clear it.
 *   - Firmware input must contain the boot signature "KENWOOD" at E580 unless
 *     --force-unsafe is supplied.
 *   - Firmware is verified by re-entering normal PROGRAM mode and reading the
 *     complete 8000-E5FF region back byte-for-byte after programming.
 *
 * IMPORTANT: The ordinary PROGRAM-mode W command is mask-ROM guarded against
 * executable addresses below E600.  Firmware therefore uses the separate
 * resident recovery loader.  The loader consumes one sacrificial serial byte
 * to enter its ASCII-HEX path, then accumulates four 16-byte records into one
 * 64-byte AT29C256 page.  The first bench test confirmed this buffering behavior
 * and exposed the required sacrificial byte; this corrected path still needs
 * a successful hardware retest.  Addressed records allow changed pages to be
 * sent without rewriting the complete firmware image.
 *
 * Build:
 *   gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk840upload tk840upload.c
 *
 * Examples:
 *   ./tk840upload /dev/ttyUSB0 codeplug codeplug.bin
 *   ./tk840upload /dev/ttyUSB0 firmware firmware.bin
 *   ./tk840upload --dry-run /dev/ttyUSB0 firmware firmware.bin
 *   ./tk840upload --force-unsafe /dev/ttyUSB0 codeplug exact-codeplug.bin
 *
 * --force-unsafe intentionally disables the recovery interlock described
 * above.  It is meant for deliberate recovery/RE work, not routine use.
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define ACK 0x06
#define NAK 0x15
#define BLOCK_SIZE 0x80u
#define FLASH_PAGE_SIZE 0x40u
#define HEX_DATA_SIZE 0x10u
#define TIMEOUT_MS 1500

#define PROGRAM_START  0x8000u
#define PROGRAM_END    0xE5FFu
#define PROGRAM_SIZE   (PROGRAM_END - PROGRAM_START + 1u)
#define CODEPLUG_START 0xE600u
#define CODEPLUG_END   0xFDFFu
#define CODEPLUG_SIZE  (CODEPLUG_END - CODEPLUG_START + 1u)

#define RECOVERY_ADDR   0xE66Cu
#define RECOVERY_OFFSET (RECOVERY_ADDR - CODEPLUG_START)
#define RECOVERY_MASK   0x04u

#define PASSWORD_ADDR   0xE670u
#define PASSWORD_OFFSET (PASSWORD_ADDR - CODEPLUG_START)
#define PASSWORD_LENGTH 10u

#define FIRMWARE_SIGNATURE_ADDR   0xE580u
#define FIRMWARE_SIGNATURE_OFFSET (FIRMWARE_SIGNATURE_ADDR - PROGRAM_START)
#define FIRMWARE_SIGNATURE        "KENWOOD"
#define FIRMWARE_SIGNATURE_LEN    7u

struct options {
    int dry_run;
    int force_unsafe;
};

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_exact_timeout(int fd, void *buf, size_t len, int timeout_ms)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;

    while (got < len) {
        struct pollfd pfd;
        int pr;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        do {
            pr = poll(&pfd, 1, timeout_ms);
        } while (pr < 0 && errno == EINTR);

        if (pr == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (pr < 0)
            return -1;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            errno = EIO;
            return -1;
        }

        {
            ssize_t n = read(fd, p + got, len - got);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                return -1;
            }
            if (n == 0)
                continue;
            got += (size_t)n;
        }
    }
    return 0;
}

static int read_exact(int fd, void *buf, size_t len)
{
    return read_exact_timeout(fd, buf, len, TIMEOUT_MS);
}

static int set_serial(int fd, speed_t speed)
{
    struct termios tio;

    if (tcgetattr(fd, &tio) < 0)
        return -1;
    cfmakeraw(&tio);
    tio.c_cflag &= ~(PARENB | PARODD | CRTSCTS | CSIZE);
    tio.c_cflag |= CS8 | CSTOPB | CLOCAL | CREAD; /* 8N2 */
    tio.c_iflag &= ~(IXON | IXOFF | IXANY);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 0;
    if (cfsetispeed(&tio, speed) < 0 || cfsetospeed(&tio, speed) < 0)
        return -1;
    if (tcsetattr(fd, TCSANOW, &tio) < 0)
        return -1;
    return 0;
}

static void assert_modem_lines(int fd)
{
#ifdef TIOCMBIS
    int bits = TIOCM_DTR | TIOCM_RTS;
    if (ioctl(fd, TIOCMBIS, &bits) < 0)
        fprintf(stderr, "warning: could not assert DTR/RTS: %s\n", strerror(errno));
#else
    (void)fd;
#endif
}

static int valid_radio_id(const char ident[8])
{
    if ((!strncmp(ident, "M890B", 5) || !strncmp(ident, "M840B", 5)) &&
        strchr("123", ident[5]) && strchr("NY", ident[6]))
        return 1;
    if (!strncmp(ident, "M940B1", 6) && strchr("NY", ident[6]))
        return 1;
    if (!strncmp(ident, "M941B1", 6) && strchr("NY", ident[6]))
        return 1;
    return 0;
}

static int read_block(int fd, uint16_t addr, uint8_t data[BLOCK_SIZE])
{
    uint8_t req[4] = { 'R', (uint8_t)(addr >> 8), (uint8_t)addr, BLOCK_SIZE };
    uint8_t first, hdr[4], ack;
    uint16_t raddr;

    if (write_all(fd, req, sizeof(req)) < 0)
        return -1;
    if (read_exact(fd, &first, 1) < 0)
        return -1;

    if (first == ACK) {
        if (read_exact(fd, hdr, sizeof(hdr)) < 0)
            return -1;
    } else if (first == 'W') {
        hdr[0] = first;
        if (read_exact(fd, hdr + 1, 3) < 0)
            return -1;
    } else {
        fprintf(stderr, "read %04X: expected ACK/W, got %02X\n", addr, first);
        errno = EPROTO;
        return -1;
    }

    raddr = ((uint16_t)hdr[1] << 8) | hdr[2];
    if (hdr[0] != 'W' || raddr != addr || hdr[3] != BLOCK_SIZE) {
        fprintf(stderr, "read %04X: bad header %02X %02X %02X %02X\n",
                addr, hdr[0], hdr[1], hdr[2], hdr[3]);
        errno = EPROTO;
        return -1;
    }
    if (read_exact(fd, data, BLOCK_SIZE) < 0)
        return -1;

    ack = ACK;
    if (write_all(fd, &ack, 1) < 0)
        return -1;
    if (read_exact(fd, &ack, 1) < 0)
        return -1;
    if (ack != ACK) {
        fprintf(stderr, "read %04X: final ACK was %02X\n", addr, ack);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int write_block(int fd, uint16_t addr, const uint8_t data[BLOCK_SIZE])
{
    uint8_t hdr[4] = { 'W', (uint8_t)(addr >> 8), (uint8_t)addr, BLOCK_SIZE };
    uint8_t ack;

    if (addr < CODEPLUG_START) {
        fprintf(stderr, "internal safety error: ordinary W attempted at %04X\n", addr);
        errno = EPERM;
        return -1;
    }
    if (write_all(fd, hdr, sizeof(hdr)) < 0 ||
        write_all(fd, data, BLOCK_SIZE) < 0)
        return -1;
    if (read_exact(fd, &ack, 1) < 0)
        return -1;
    if (ack != ACK) {
        fprintf(stderr, "write %04X: expected ACK, got %02X\n", addr, ack);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int authenticate_if_needed(int fd, const char ident[8])
{
    uint8_t block[BLOCK_SIZE];
    uint8_t msg[1 + PASSWORD_LENGTH];
    uint8_t ack;
    size_t off = PASSWORD_ADDR - CODEPLUG_START;

    if (ident[6] != 'Y')
        return 0;

    fprintf(stderr, "Radio reports password protection; recovering stored password...\n");
    if (read_block(fd, CODEPLUG_START, block) < 0) {
        perror("reading password block E600");
        return -1;
    }
    if (off + PASSWORD_LENGTH > BLOCK_SIZE) {
        errno = EINVAL;
        return -1;
    }
    msg[0] = 0x04;
    memcpy(msg + 1, block + off, PASSWORD_LENGTH);
    if (write_all(fd, msg, sizeof(msg)) < 0 || read_exact(fd, &ack, 1) < 0) {
        perror("password authentication");
        return -1;
    }
    if (ack != ACK) {
        fprintf(stderr, "Recovered password rejected, reply=%02X\n", ack);
        errno = EACCES;
        return -1;
    }
    fprintf(stderr, "Password accepted.\n");
    return 0;
}

static int enter_program_mode(int fd, char ident[8])
{
    static const uint8_t program[] = "PROGRAM";
    uint8_t b;

    if (set_serial(fd, B1200) < 0)
        return -1;
    assert_modem_lines(fd);
    tcflush(fd, TCIOFLUSH);

    if (write_all(fd, program, sizeof(program) - 1) < 0 || read_exact(fd, &b, 1) < 0)
        return -1;
    if (b != ACK) {
        fprintf(stderr, "PROGRAM: expected ACK 06, got %02X\n", b);
        errno = EPROTO;
        return -1;
    }

    usleep(50000);
    if (set_serial(fd, B9600) < 0)
        return -1;
    assert_modem_lines(fd);
    usleep(50000);

    b = 0x02;
    if (write_all(fd, &b, 1) < 0 || read_exact(fd, ident, 7) < 0)
        return -1;
    ident[7] = '\0';

    if (!valid_radio_id(ident)) {
        fprintf(stderr, "Unexpected radio identification: '%s'\n", ident);
        errno = ENODEV;
        return -1;
    }

    b = ACK;
    if (write_all(fd, &b, 1) < 0)
        return -1;

    fprintf(stderr, "Connected: %s\n", ident);
    if (authenticate_if_needed(fd, ident) < 0)
        return -1;
    return 0;
}

static void exit_program_mode(int fd)
{
    uint8_t e = 'E';
    if (write_all(fd, &e, 1) < 0)
        fprintf(stderr, "warning: could not send E: %s\n", strerror(errno));
    tcdrain(fd);
    usleep(50000);
}

static int read_region(int fd, uint16_t start, size_t len, uint8_t *out,
                       const char *what)
{
    size_t pos;
    if ((start & (BLOCK_SIZE - 1u)) || (len & (BLOCK_SIZE - 1u))) {
        errno = EINVAL;
        return -1;
    }
    for (pos = 0; pos < len; pos += BLOCK_SIZE) {
        uint16_t addr = (uint16_t)(start + pos);
        fprintf(stderr, "\rReading %-9s %04X-%04X", what, addr,
                (unsigned)(addr + BLOCK_SIZE - 1u));
        fflush(stderr);
        if (read_block(fd, addr, out + pos) < 0) {
            fprintf(stderr, "\n");
            return -1;
        }
    }
    fprintf(stderr, "\n");
    return 0;
}

static int read_file_exact(const char *path, uint8_t *buf, size_t expected)
{
    FILE *f = fopen(path, "rb");
    struct stat st;
    size_t n;
    if (!f) {
        perror(path);
        return -1;
    }
    if (fstat(fileno(f), &st) < 0) {
        perror("fstat");
        fclose(f);
        return -1;
    }
    if (st.st_size != (off_t)expected) {
        fprintf(stderr, "%s: expected exactly %zu bytes, got %lld\n",
                path, expected, (long long)st.st_size);
        fclose(f);
        return -1;
    }
    n = fread(buf, 1, expected, f);
    if (n != expected) {
        perror("reading input image");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static uint16_t byte_sum16(const uint8_t *p, size_t len)
{
    uint32_t s = 0;
    size_t i;
    for (i = 0; i < len; ++i)
        s += p[i];
    return (uint16_t)s;
}

static size_t mismatch_count(const uint8_t *a, const uint8_t *b, size_t len,
                             uint32_t base, int show)
{
    size_t i, n = 0;
    unsigned shown = 0;
    for (i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            ++n;
            if (show && shown < 16) {
                fprintf(stderr, "  mismatch %04X: radio=%02X file=%02X\n",
                        (unsigned)(base + i), a[i], b[i]);
                ++shown;
            }
        }
    }
    if (show && n > shown)
        fprintf(stderr, "  ... plus %zu more mismatched bytes\n", n - shown);
    return n;
}

static int verify_block_exact(int fd, uint16_t addr, const uint8_t target[BLOCK_SIZE])
{
    uint8_t check[BLOCK_SIZE];
    if (read_block(fd, addr, check) < 0)
        return -1;
    if (memcmp(check, target, BLOCK_SIZE) != 0) {
        fprintf(stderr, "Verification failed immediately after write at %04X\n", addr);
        mismatch_count(check, target, BLOCK_SIZE, addr, 1);
        errno = EIO;
        return -1;
    }
    return 0;
}

static int force_recovery_flag_in_session(int fd, int dry_run)
{
    uint8_t block[BLOCK_SIZE], target[BLOCK_SIZE];
    size_t in_block = RECOVERY_ADDR - CODEPLUG_START;

    if (read_block(fd, CODEPLUG_START, block) < 0)
        return -1;
    if (in_block >= BLOCK_SIZE) {
        errno = EINVAL;
        return -1;
    }

    if (block[in_block] & RECOVERY_MASK) {
        fprintf(stderr, "Recovery interlock already enabled: E66C=%02X (bit 2 set).\n",
                block[in_block]);
        return 0;
    }

    fprintf(stderr, "Recovery interlock is OFF: E66C=%02X.\n", block[in_block]);
    if (dry_run) {
        fprintf(stderr, "DRY RUN: would set E66C bit 2 before firmware programming.\n");
        return 0;
    }

    memcpy(target, block, sizeof(target));
    target[in_block] |= RECOVERY_MASK;
    fprintf(stderr, "Setting recovery interlock E66C bit 2: %02X -> %02X\n",
            block[in_block], target[in_block]);
    if (write_block(fd, CODEPLUG_START, target) < 0)
        return -1;
    if (verify_block_exact(fd, CODEPLUG_START, target) < 0)
        return -1;
    fprintf(stderr, "Recovery interlock verified ON.\n");
    return 0;
}

static int upload_codeplug(int fd, const char *path, const struct options *opt)
{
    uint8_t *current = malloc(CODEPLUG_SIZE);
    uint8_t *target = malloc(CODEPLUG_SIZE);
    uint8_t *verify = malloc(CODEPLUG_SIZE);
    size_t block, changed = 0, bytes_changed;
    int rc = -1;

    if (!current || !target || !verify) {
        perror("malloc");
        goto out;
    }
    if (read_file_exact(path, target, CODEPLUG_SIZE) < 0)
        goto out;

    if (!opt->force_unsafe) {
        uint8_t old = target[RECOVERY_OFFSET];
        target[RECOVERY_OFFSET] |= RECOVERY_MASK;
        if (old != target[RECOVERY_OFFSET])
            fprintf(stderr,
                    "Safety: forcing codeplug recovery bit ON at offset 006C: %02X -> %02X\n",
                    old, target[RECOVERY_OFFSET]);
    } else if (!(target[RECOVERY_OFFSET] & RECOVERY_MASK)) {
        fprintf(stderr,
                "*** UNSAFE OVERRIDE: target codeplug clears E66C bit 2. ***\n"
                "*** The exact image will be written because --force-unsafe was used. ***\n");
    }

    if (read_region(fd, CODEPLUG_START, CODEPLUG_SIZE, current, "codeplug") < 0) {
        perror("reading live codeplug");
        goto out;
    }

    bytes_changed = mismatch_count(current, target, CODEPLUG_SIZE, CODEPLUG_START, 0);
    for (block = 0; block < CODEPLUG_SIZE / BLOCK_SIZE; ++block)
        if (memcmp(current + block * BLOCK_SIZE,
                   target + block * BLOCK_SIZE, BLOCK_SIZE) != 0)
            ++changed;

    fprintf(stderr, "Codeplug differences: %zu byte(s), %zu changed 0x80-byte block(s).\n",
            bytes_changed, changed);
    if (!changed) {
        fprintf(stderr, "Nothing to write. Live codeplug already matches target.\n");
        rc = 0;
        goto out;
    }
    if (opt->dry_run) {
        for (block = 0; block < CODEPLUG_SIZE / BLOCK_SIZE; ++block) {
            if (memcmp(current + block * BLOCK_SIZE,
                       target + block * BLOCK_SIZE, BLOCK_SIZE) != 0)
                fprintf(stderr, "  would write %04X-%04X\n",
                        (unsigned)(CODEPLUG_START + block * BLOCK_SIZE),
                        (unsigned)(CODEPLUG_START + (block + 1) * BLOCK_SIZE - 1));
        }
        fprintf(stderr, "DRY RUN: no writes performed.\n");
        rc = 0;
        goto out;
    }

    for (block = 0; block < CODEPLUG_SIZE / BLOCK_SIZE; ++block) {
        uint16_t addr;
        uint8_t *p;
        if (memcmp(current + block * BLOCK_SIZE,
                   target + block * BLOCK_SIZE, BLOCK_SIZE) == 0)
            continue;
        addr = (uint16_t)(CODEPLUG_START + block * BLOCK_SIZE);
        p = target + block * BLOCK_SIZE;
        fprintf(stderr, "Writing changed codeplug block %04X-%04X...\n",
                addr, (unsigned)(addr + BLOCK_SIZE - 1));
        if (write_block(fd, addr, p) < 0) {
            perror("codeplug write");
            goto out;
        }
        if (verify_block_exact(fd, addr, p) < 0) {
            perror("codeplug immediate verify");
            goto out;
        }
    }

    fprintf(stderr, "Performing full codeplug readback verification...\n");
    if (read_region(fd, CODEPLUG_START, CODEPLUG_SIZE, verify, "verify") < 0)
        goto out;
    if (memcmp(verify, target, CODEPLUG_SIZE) != 0) {
        fprintf(stderr, "CODEPLUG VERIFY FAILED.\n");
        mismatch_count(verify, target, CODEPLUG_SIZE, CODEPLUG_START, 1);
        goto out;
    }
    fprintf(stderr, "Codeplug verified byte-for-byte.\n");
    rc = 0;

out:
    free(current);
    free(target);
    free(verify);
    return rc;
}

static char hex_digit(unsigned v)
{
    return "0123456789ABCDEF"[v & 0x0F];
}

/* Build a standard Intel-HEX data record.  The TK-840 mask parser uses the
 * byte count, 16-bit firmware-relative address and data.  Sending a valid
 * Intel checksum costs nothing and keeps the stream self-consistent even
 * though the decoded resident parser does not appear to validate it. */
static size_t make_hex_record(char *out, size_t out_size, uint16_t rel_addr,
                              const uint8_t *data, uint8_t len)
{
    uint8_t sum = 0, ck;
    size_t pos = 0;
    unsigned i;
#define PUTHEX(b) do { \
    uint8_t _v = (uint8_t)(b); \
    if (pos + 2 >= out_size) return 0; \
    out[pos++] = hex_digit(_v >> 4); \
    out[pos++] = hex_digit(_v); \
} while (0)

    if (out_size < 16 || len > 0x40)
        return 0;
    out[pos++] = ':';
    PUTHEX(len); sum = (uint8_t)(sum + len);
    PUTHEX(rel_addr >> 8); sum = (uint8_t)(sum + (rel_addr >> 8));
    PUTHEX(rel_addr); sum = (uint8_t)(sum + rel_addr);
    PUTHEX(0x00); /* data record */
    for (i = 0; i < len; ++i) {
        PUTHEX(data[i]);
        sum = (uint8_t)(sum + data[i]);
    }
    ck = (uint8_t)(0u - sum);
    PUTHEX(ck);
    if (pos + 2 >= out_size)
        return 0;
    out[pos++] = '\r';
    out[pos++] = '\n';
    out[pos] = '\0';
#undef PUTHEX
    return pos;
}

static int send_firmware_page(int fd, uint16_t rel_page,
                              const uint8_t data[FLASH_PAGE_SIZE])
{
    unsigned n;
    for (n = 0; n < FLASH_PAGE_SIZE; n += HEX_DATA_SIZE) {
        char rec[80];
        size_t len = make_hex_record(rec, sizeof(rec),
                                     (uint16_t)(rel_page + n),
                                     data + n, HEX_DATA_SIZE);
        if (!len) {
            errno = EOVERFLOW;
            return -1;
        }
        if (write_all(fd, rec, len) < 0)
            return -1;
    }
    if (tcdrain(fd) < 0)
        return -1;
    /* The AT29C256 writer includes a resident completion delay, but a small
     * host-side gap also prevents overrunning the receiver between pages. */
    usleep(20000);
    return 0;
}

static int prompt_enter(const char *message)
{
    char line[32];
    fputs(message, stderr);
    fflush(stderr);
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "\nInput cancelled.\n");
        return -1;
    }
    return 0;
}

static int reopen_program_for_verify(int fd, char ident[8])
{
    int tries;
    for (tries = 0; tries < 3; ++tries) {
        if (enter_program_mode(fd, ident) == 0)
            return 0;
        if (tries != 2) {
            fprintf(stderr,
                    "Could not re-enter PROGRAM mode for verification (%s).\n",
                    strerror(errno));
            if (prompt_enter(
                    "Make sure the radio is powered normally (release the recovery key), "
                    "then press Enter to retry: ") < 0)
                return -1;
        }
    }
    return -1;
}

static int upload_firmware(int fd, const char *path, const struct options *opt,
                           char ident[8])
{
    uint8_t *current = malloc(PROGRAM_SIZE);
    uint8_t *target = malloc(PROGRAM_SIZE);
    uint8_t *verify = malloc(PROGRAM_SIZE);
    uint8_t *changed = calloc(PROGRAM_SIZE / FLASH_PAGE_SIZE, 1);
    size_t page, changed_pages = 0, changed_bytes;
    int rc = -1;
    int program_active = 1;

    if (!current || !target || !verify || !changed) {
        perror("malloc");
        goto out;
    }
    if (read_file_exact(path, target, PROGRAM_SIZE) < 0)
        goto out;

    fprintf(stderr, "Target firmware byte-sum: %04X\n", byte_sum16(target, PROGRAM_SIZE));
    if (memcmp(target + FIRMWARE_SIGNATURE_OFFSET,
               FIRMWARE_SIGNATURE, FIRMWARE_SIGNATURE_LEN) != 0) {
        fprintf(stderr,
                "WARNING: target lacks the expected KENWOOD boot signature at E580.\n");
        if (!opt->force_unsafe) {
            fprintf(stderr,
                    "Refusing firmware write. Use --force-unsafe only if this is deliberate.\n");
            goto out;
        }
        fprintf(stderr, "*** UNSAFE OVERRIDE: continuing without KENWOOD signature. ***\n");
    }

    if (read_region(fd, PROGRAM_START, PROGRAM_SIZE, current, "firmware") < 0) {
        perror("reading live firmware");
        goto out;
    }
    fprintf(stderr, "Live firmware byte-sum  : %04X\n", byte_sum16(current, PROGRAM_SIZE));

    changed_bytes = mismatch_count(current, target, PROGRAM_SIZE, PROGRAM_START, 0);
    for (page = 0; page < PROGRAM_SIZE / FLASH_PAGE_SIZE; ++page) {
        if (memcmp(current + page * FLASH_PAGE_SIZE,
                   target + page * FLASH_PAGE_SIZE, FLASH_PAGE_SIZE) != 0) {
            changed[page] = 1;
            ++changed_pages;
        }
    }
    fprintf(stderr,
            "Firmware differences: %zu byte(s), %zu changed 64-byte flash page(s).\n",
            changed_bytes, changed_pages);

    if (!changed_pages) {
        fprintf(stderr, "Nothing to write. Live firmware already matches target.\n");
        rc = 0;
        goto out;
    }

    if (opt->dry_run) {
        for (page = 0; page < PROGRAM_SIZE / FLASH_PAGE_SIZE; ++page) {
            if (changed[page]) {
                unsigned a = PROGRAM_START + (unsigned)(page * FLASH_PAGE_SIZE);
                fprintf(stderr, "  would program %04X-%04X\n", a,
                        a + FLASH_PAGE_SIZE - 1u);
            }
        }
        if (!opt->force_unsafe)
            fprintf(stderr, "DRY RUN: recovery E66C bit 2 would be forced ON first.\n");
        fprintf(stderr, "DRY RUN: no writes performed.\n");
        rc = 0;
        goto out;
    }

    if (!opt->force_unsafe) {
        if (force_recovery_flag_in_session(fd, 0) < 0) {
            fprintf(stderr, "Cannot establish/verify firmware recovery interlock; aborting.\n");
            goto out;
        }
    } else {
        uint8_t block[BLOCK_SIZE];
        size_t off = RECOVERY_ADDR - CODEPLUG_START;
        if (read_block(fd, CODEPLUG_START, block) < 0)
            goto out;
        fprintf(stderr,
                "*** --force-unsafe active: E66C=%02X, recovery bit is %s. ***\n",
                block[off], (block[off] & RECOVERY_MASK) ? "ON" : "OFF");
        if (!(block[off] & RECOVERY_MASK))
            fprintf(stderr,
                    "*** Firmware programming will proceed WITHOUT the recovery interlock. ***\n");
    }

    fprintf(stderr,
            "\nFirmware write requires the resident recovery loader.\n"
            "The recovery flag is now protected unless --force-unsafe was used.\n"
            "The common boot ROM gates panel event 0x84 with E66C bit 2.\n"
            "On the TK-941-family FPRO procedure this is entered by holding\n"
            "SYSTEM UP while powering on until the display shows PROG.\n");

    exit_program_mode(fd);
    program_active = 0;

    if (prompt_enter(
            "Hold SYSTEM UP, power-cycle into PROG/recovery mode, then press Enter: ") < 0)
        goto out;

    if (set_serial(fd, B9600) < 0) {
        perror("setting loader serial to 9600 8N2");
        goto out;
    }
    assert_modem_lines(fd);
    tcflush(fd, TCIFLUSH);
    usleep(100000);

    /* The resident loader uses the first received serial byte only to select
     * the ASCII-HEX receive path.  That byte is discarded before the parser
     * begins scanning for the first ':' record marker.  Send a sacrificial
     * CR here so the first actual HEX record is not silently lost. */
    if (write_all(fd, "\r", 1) < 0 || tcdrain(fd) < 0) {
        perror("synchronizing firmware loader");
        goto out;
    }
    usleep(20000);

    fprintf(stderr, "Programming %zu changed firmware page(s)...\n", changed_pages);
    {
        size_t done = 0;
        for (page = 0; page < PROGRAM_SIZE / FLASH_PAGE_SIZE; ++page) {
            uint16_t rel;
            unsigned a;
            if (!changed[page])
                continue;
            rel = (uint16_t)(page * FLASH_PAGE_SIZE);
            a = PROGRAM_START + rel;
            fprintf(stderr, "\rFirmware page %zu/%zu: %04X-%04X",
                    ++done, changed_pages, a, a + FLASH_PAGE_SIZE - 1u);
            fflush(stderr);
            if (send_firmware_page(fd, rel, target + page * FLASH_PAGE_SIZE) < 0) {
                fprintf(stderr, "\n");
                perror("sending firmware page");
                goto out;
            }
        }
        fprintf(stderr, "\n");
    }

    /* Zero-length record selects the decoded loader's finalization path.  It
     * deliberately contains only the byte count; the parser branches as soon
     * as it decodes length=0 and does not require the rest of an Intel EOF. */
    if (write_all(fd, ":00\r\n", 5) < 0 || tcdrain(fd) < 0) {
        perror("finalizing firmware loader");
        goto out;
    }
    fprintf(stderr, "Firmware stream complete.\n");

    if (prompt_enter(
            "Release the recovery key and power-cycle the radio normally if needed. "
            "Press Enter to perform full readback verification: ") < 0)
        goto out;

    if (reopen_program_for_verify(fd, ident) < 0) {
        fprintf(stderr,
                "FIRMWARE VERIFY FAILED: unable to re-enter PROGRAM mode.\n"
                "The upload is NOT being reported as successful. The recovery flag\n"
                "was left enabled unless --force-unsafe was used.\n");
        goto out;
    }
    program_active = 1;

    if (read_region(fd, PROGRAM_START, PROGRAM_SIZE, verify, "verify") < 0) {
        perror("firmware readback");
        goto out;
    }
    if (memcmp(verify, target, PROGRAM_SIZE) != 0) {
        fprintf(stderr, "FIRMWARE VERIFY FAILED.\n");
        mismatch_count(verify, target, PROGRAM_SIZE, PROGRAM_START, 1);
        goto out;
    }
    fprintf(stderr,
            "Firmware verified byte-for-byte. Readback byte-sum: %04X\n",
            byte_sum16(verify, PROGRAM_SIZE));
    rc = 0;

out:
    if (rc != 0 && program_active)
        exit_program_mode(fd);
    free(current);
    free(target);
    free(verify);
    free(changed);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [--dry-run] [--force-unsafe] <serial-device> codeplug <image.bin>\n"
        "  %s [--dry-run] [--force-unsafe] <serial-device> firmware <image.bin>\n"
        "\n"
        "Images must be exact raw sizes:\n"
        "  codeplug  E600-FDFF  0x1800 bytes\n"
        "  firmware  8000-E5FF  0x6600 bytes\n"
        "\n"
        "Default safety behavior:\n"
        "  * read live image first; write only changed blocks/pages\n"
        "  * verify all writes by readback\n"
        "  * force codeplug E66C bit 2 ON (firmware recovery interlock)\n"
        "  * firmware requires KENWOOD signature at E580\n"
        "\n"
        "--dry-run       read/compare/plan only; never write\n"
        "--force-unsafe  do not force the recovery flag; permit codeplug images\n"
        "                that clear it and firmware images without KENWOOD signature\n"
        "\n"
        "WARNING: firmware loading uses a reverse-engineered resident-loader path.\n"
        "One hardware test exposed and confirmed the loader's sacrificial sync-byte\n"
        "behavior; the corrected firmware path still requires a successful retest.\n"
        "Codeplug W transactions use the already verified KPG/CHIRP protocol.\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    struct options opt = {0, 0};
    const char *device, *mode, *path;
    int argi = 1, fd = -1, rc = 1;
    char ident[8];

    while (argi < argc && !strncmp(argv[argi], "--", 2)) {
        if (!strcmp(argv[argi], "--dry-run"))
            opt.dry_run = 1;
        else if (!strcmp(argv[argi], "--force-unsafe"))
            opt.force_unsafe = 1;
        else if (!strcmp(argv[argi], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[argi]);
            usage(argv[0]);
            return 1;
        }
        ++argi;
    }

    if (argc - argi != 3) {
        usage(argv[0]);
        return 1;
    }
    device = argv[argi++];
    mode = argv[argi++];
    path = argv[argi++];

    if (strcmp(mode, "codeplug") && strcmp(mode, "channels") &&
        strcmp(mode, "firmware") && strcmp(mode, "program")) {
        fprintf(stderr, "Mode must be codeplug/channels or firmware/program.\n");
        return 1;
    }

    fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror(device);
        return 1;
    }
    if (enter_program_mode(fd, ident) < 0) {
        perror("entering PROGRAM mode");
        goto out;
    }

    if (!strcmp(mode, "codeplug") || !strcmp(mode, "channels")) {
        if (upload_codeplug(fd, path, &opt) == 0)
            rc = 0;
        exit_program_mode(fd);
    } else {
        if (upload_firmware(fd, path, &opt, ident) == 0)
            rc = 0;
        /* upload_firmware may have re-entered PROGRAM mode for verify.  E is
         * harmlessly attempted here only when normal monitor is active; if not,
         * write failure is merely reported as a warning by exit_program_mode. */
        if (rc == 0)
            exit_program_mode(fd);
    }

out:
    if (fd >= 0)
        close(fd);
    return rc;
}
