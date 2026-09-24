/*
 * tk840dump.c - Read/validate memory from a Kenwood TK-840-family radio
 *               using the verified KPG-25D/CHIRP clone-read protocol.
 * Copyright 2026 by Dave "WormFood" <kenwood-tk-x4x@wormfood.net>
 * *
 * Linux/POSIX.  This program is intentionally READ ONLY: it never issues
 * the radio's write command.
 *
 * SAFETY NOTES
 *
 * This utility is based on reverse-engineering of the Kenwood programming
 * protocol and memory map.  It has been tested on the TK-840; related models
 * and other firmware revisions may behave differently.
 *
 * "Read only" at the programming-protocol level does NOT mean that every CPU
 * address is safe to read.  In particular, reading the MCU's SFR space
 * (0xFF00-0xFFFF) may alter peripheral state, access undefined registers, or
 * otherwise cause unpredictable radio/MCU behavior.  SFR access is provided
 * deliberately for reverse-engineering purposes and is used at your own risk.
 *
 * Internal RAM is live working memory.  Its contents may change while a dump
 * is in progress, so a RAM dump is not necessarily a coherent snapshot.
 * Unmapped address space may return meaningless/open-bus data.
 *
 * The Kenwood firmware checksum printed for 0x8000-0xE5FF is a 16-bit byte
 * sum used as a firmware identifier.  It is not a cryptographic integrity
 * check; SHA-256 is also printed for archival/file identification.
 *
 * Named dump examples:
 *   tk840dump /dev/ttyUSB0 bootrom  bootrom.bin
 *   tk840dump /dev/ttyUSB0 program  firmware.bin
 *   tk840dump /dev/ttyUSB0 channels codeplug.bin
 *   tk840dump /dev/ttyUSB0 ram      ram.bin
 *
 * Manual range:
 *   tk840dump /dev/ttyUSB0 0x8000 0xe5ff firmware.bin
 *
 * Validate a file against the live radio:
 *   tk840dump /dev/ttyUSB0 validate program firmware.bin
 *   tk840dump /dev/ttyUSB0 validate 0x8000 0xe5ff firmware.bin
 *
 * start/end are inclusive and may be decimal or 0x-prefixed hexadecimal.
 * The radio protocol has only been verified with 0x80-byte read transactions,
 * so this utility reads complete 128-byte blocks and uses only the bytes
 * requested by the selected range.
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

#define ACK         0x06
#define NAK         0x15
#define BLOCK_SIZE  0x80
#define TIMEOUT_MS  1500

#define BOOTROM_START   0x0000u
#define BOOTROM_END     0x1FFFu
#define PROGRAM_START   0x8000u
#define PROGRAM_END     0xE5FFu
#define CHANNELS_START  0xE600u
#define CHANNELS_END    0xFDFFu
#define RAM_START       0xFE00u
#define RAM_END         0xFEFFu
#define SFR_START       0xFF00u
#define SFR_END         0xFFFFu

#define EXIT_MISMATCH   2
#define MAX_MISMATCHES_SHOWN 32

struct region {
    const char *name;
    uint32_t start;
    uint32_t end;
    const char *description;
};

static const struct region regions[] = {
    { "bootrom",  BOOTROM_START,  BOOTROM_END,  "internal mask/boot ROM" },
    { "program",  PROGRAM_START,  PROGRAM_END,  "external executable firmware" },
    { "channels", CHANNELS_START, CHANNELS_END, "channel/codeplug/configuration" },
    { "ram",      RAM_START,      RAM_END,      "internal RAM" },
    { "sfr",      SFR_START,      SFR_END,      "special-function registers" },
};

/* ----------------------------- SHA-256 ----------------------------- */

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
    size_t used;
};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_transform(struct sha256_ctx *ctx, const uint8_t block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
        0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
        0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
        0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
        0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
        0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
        0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
        0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
        0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,h;
    unsigned i;

    for (i = 0; i < 16; ++i)
        w[i] = load_be32(block + i * 4);
    for (; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(struct sha256_ctx *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bitcount = 0;
    ctx->used = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bitcount += (uint64_t)len * 8u;
    while (len) {
        size_t n = 64 - ctx->used;
        if (n > len)
            n = len;
        memcpy(ctx->buffer + ctx->used, data, n);
        ctx->used += n;
        data += n;
        len -= n;
        if (ctx->used == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->used = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *ctx, uint8_t digest[32])
{
    uint64_t bits = ctx->bitcount;
    unsigned i;

    ctx->buffer[ctx->used++] = 0x80;
    if (ctx->used > 56) {
        while (ctx->used < 64)
            ctx->buffer[ctx->used++] = 0;
        sha256_transform(ctx, ctx->buffer);
        ctx->used = 0;
    }
    while (ctx->used < 56)
        ctx->buffer[ctx->used++] = 0;

    for (i = 0; i < 8; ++i)
        ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; ++i)
        store_be32(digest + i * 4, ctx->state[i]);
}

struct checksums {
    uint16_t kenwood_sum;
    uint16_t crc16;
    struct sha256_ctx sha;
};

static void checksums_init(struct checksums *c)
{
    c->kenwood_sum = 0;
    c->crc16 = 0xFFFFu; /* CRC-16/CCITT-FALSE */
    sha256_init(&c->sha);
}

static void checksums_update(struct checksums *c, const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        unsigned bit;
        c->kenwood_sum = (uint16_t)(c->kenwood_sum + data[i]);
        c->crc16 ^= (uint16_t)data[i] << 8;
        for (bit = 0; bit < 8; ++bit)
            c->crc16 = (c->crc16 & 0x8000u) ?
                (uint16_t)((c->crc16 << 1) ^ 0x1021u) :
                (uint16_t)(c->crc16 << 1);
    }
    sha256_update(&c->sha, data, len);
}

static void print_checksums(const char *label, struct checksums *c)
{
    uint8_t digest[32];
    unsigned i;

    sha256_final(&c->sha, digest);
    fprintf(stderr, "%s:\n", label);
    fprintf(stderr, "  Kenwood firmware checksum : %04X\n", c->kenwood_sum);
    fprintf(stderr, "  CRC-16/CCITT-FALSE        : %04X\n", c->crc16);
    fprintf(stderr, "  SHA-256                   : ");
    for (i = 0; i < sizeof(digest); ++i)
        fprintf(stderr, "%02x", digest[i]);
    fputc('\n', stderr);
}

/* --------------------------- serial protocol --------------------------- */

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

/* Match the CHIRP driver's behavior: allow partial reads and give each
 * arriving chunk another TIMEOUT_MS for the rest of the transaction. */
static int read_exact(int fd, void *buf, size_t len)
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
            pr = poll(&pfd, 1, TIMEOUT_MS);
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

static int set_serial(int fd, speed_t speed)
{
    struct termios tio;

    if (tcgetattr(fd, &tio) < 0)
        return -1;

    cfmakeraw(&tio);
    tio.c_cflag &= ~(PARENB | PARODD | CRTSCTS | CSIZE);
    tio.c_cflag |= CS8 | CSTOPB | CLOCAL | CREAD;   /* 8N2 */
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
    if (ioctl(fd, TIOCMBIS, &bits) < 0) {
        fprintf(stderr,
                "warning: could not assert DTR/RTS: %s\n",
                strerror(errno));
    }
#else
    (void)fd;
#endif
}

static int enter_program_mode(int fd, char ident[8])
{
    static const uint8_t program[] = "PROGRAM";
    uint8_t b;

    if (set_serial(fd, B1200) < 0) {
        perror("setting 1200 8N2");
        return -1;
    }
    assert_modem_lines(fd);
    tcflush(fd, TCIFLUSH);

    if (write_all(fd, program, sizeof(program) - 1) < 0) {
        perror("sending PROGRAM");
        return -1;
    }
    if (read_exact(fd, &b, 1) < 0) {
        perror("waiting for PROGRAM ACK");
        return -1;
    }
    if (b != ACK) {
        fprintf(stderr, "PROGRAM: expected ACK 06, got %02X\n", b);
        return -1;
    }

    usleep(50000);

    if (set_serial(fd, B9600) < 0) {
        perror("setting 9600 8N2");
        return -1;
    }
    assert_modem_lines(fd);
    usleep(50000);

    b = 0x02;
    if (write_all(fd, &b, 1) < 0) {
        perror("sending identification request");
        return -1;
    }
    if (read_exact(fd, ident, 7) < 0) {
        perror("reading radio identification");
        return -1;
    }
    ident[7] = '\0';

    /* KPG-25D/CHIRP sends this ACK one-way.  Do not wait for a response. */
    b = ACK;
    if (write_all(fd, &b, 1) < 0) {
        perror("ACKing radio identification");
        return -1;
    }

    return 0;
}

static void exit_program_mode(int fd)
{
    uint8_t e = 'E';

    /* A real TK-840 has been observed to send no reply here, so do not
     * require an ACK. */
    if (write_all(fd, &e, 1) < 0)
        fprintf(stderr, "warning: could not send exit command: %s\n",
                strerror(errno));
    usleep(50000);
}

static int read_block(int fd, uint16_t addr, uint8_t data[BLOCK_SIZE])
{
    uint8_t req[4];
    uint8_t first;
    uint8_t hdr[4];
    uint8_t ack;
    uint16_t raddr;

    req[0] = 'R';
    req[1] = (uint8_t)(addr >> 8);
    req[2] = (uint8_t)(addr & 0xff);
    req[3] = BLOCK_SIZE;

    if (write_all(fd, req, sizeof(req)) < 0) {
        perror("sending read request");
        return -1;
    }

    if (read_exact(fd, &first, 1) < 0) {
        perror("reading response prefix");
        return -1;
    }

    if (first == ACK) {
        if (read_exact(fd, hdr, sizeof(hdr)) < 0) {
            perror("reading response header");
            return -1;
        }
    } else if (first == 'W') {
        hdr[0] = first;
        if (read_exact(fd, hdr + 1, 3) < 0) {
            perror("reading response header");
            return -1;
        }
    } else {
        if (first == NAK)
            fprintf(stderr, "read %04X: radio returned NAK (15)\n", addr);
        else
            fprintf(stderr,
                    "read %04X: expected ACK (06) or W (57), got %02X\n",
                    addr, first);
        return -1;
    }

    raddr = ((uint16_t)hdr[1] << 8) | hdr[2];
    if (hdr[0] != 'W' || raddr != addr || hdr[3] != BLOCK_SIZE) {
        fprintf(stderr,
                "read %04X: bad header: %02X %02X %02X %02X\n",
                addr, hdr[0], hdr[1], hdr[2], hdr[3]);
        return -1;
    }

    if (read_exact(fd, data, BLOCK_SIZE) < 0) {
        perror("reading block payload");
        return -1;
    }

    ack = ACK;
    if (write_all(fd, &ack, 1) < 0) {
        perror("sending block ACK");
        return -1;
    }
    if (read_exact(fd, &ack, 1) < 0) {
        perror("reading block ACK");
        return -1;
    }
    if (ack != ACK) {
        fprintf(stderr, "read %04X: expected final ACK 06, got %02X\n",
                addr, ack);
        return -1;
    }

    return 0;
}

/* ------------------------------ CLI ------------------------------ */

static int parse_addr(const char *s, uint32_t *value)
{
    char *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if (errno || *s == '\0' || *end != '\0' || v > 0xffffUL)
        return -1;

    *value = (uint32_t)v;
    return 0;
}

static const struct region *find_region(const char *name)
{
    size_t i;
    const char *canonical = name;

    if (!strcmp(name, "rom") || !strcmp(name, "maskrom"))
        canonical = "bootrom";
    else if (!strcmp(name, "firmware") || !strcmp(name, "prog"))
        canonical = "program";
    else if (!strcmp(name, "channel") || !strcmp(name, "codeplug"))
        canonical = "channels";
    else if (!strcmp(name, "registers") || !strcmp(name, "regs"))
        canonical = "sfr";

    for (i = 0; i < sizeof(regions)/sizeof(regions[0]); ++i)
        if (!strcmp(canonical, regions[i].name))
            return &regions[i];
    return NULL;
}

static int is_program_range(uint32_t start, uint32_t end)
{
    return start == PROGRAM_START && end == PROGRAM_END;
}

static int ranges_overlap(uint32_t a_start, uint32_t a_end,
                          uint32_t b_start, uint32_t b_end)
{
    return a_start <= b_end && b_start <= a_end;
}

static void warn_selected_range(uint32_t start, uint32_t end)
{
    if (ranges_overlap(start, end, SFR_START, SFR_END)) {
        fprintf(stderr,
                "WARNING: selected range overlaps SFR space FF00-FFFF.\n"
                "         Reading arbitrary SFRs may alter peripheral state,\n"
                "         access undefined registers, or cause unpredictable behavior.\n"
                "         Continuing because SFR access was explicitly requested.\n");
    }

    if (ranges_overlap(start, end, RAM_START, RAM_END)) {
        fprintf(stderr,
                "NOTE: selected range overlaps live internal RAM FE00-FEFF;\n"
                "      contents may change while the dump/validation is in progress.\n");
    }

    if (ranges_overlap(start, end, 0x2000u, 0x7FFFu)) {
        fprintf(stderr,
                "NOTE: selected range overlaps 2000-7FFF, which appears unmapped on\n"
                "      the tested TK-840. Returned values may be open-bus/meaningless.\n");
    }
}

static const char *classify_radio_id(const char ident[8])
{
    if ((!strncmp(ident, "M890B", 5) || !strncmp(ident, "M840B", 5)) &&
        strchr("123", ident[5]) && strchr("NY", ident[6]))
        return "recognized TK-840-family ID format";

    if (!strncmp(ident, "M940B1", 6) && strchr("NY", ident[6]))
        return "recognized TK-940 ID format (not yet hardware-tested here)";

    if (!strncmp(ident, "M941B1", 6) && strchr("NY", ident[6]))
        return "recognized TK-941 ID format (not yet hardware-tested here)";

    return NULL;
}

static void print_regions(void)
{
    size_t i;
    fprintf(stderr, "Named regions:\n");
    for (i = 0; i < sizeof(regions)/sizeof(regions[0]); ++i)
        fprintf(stderr, "  %-8s %04X-%04X  %s\n",
                regions[i].name,
                (unsigned)regions[i].start,
                (unsigned)regions[i].end,
                regions[i].description);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s <serial-device> <region> <output.bin>\n"
            "  %s <serial-device> <start> <end> <output.bin>\n"
            "  %s <serial-device> validate <region> <input.bin>\n"
            "  %s <serial-device> validate <start> <end> <input.bin>\n"
            "\n"
            "start/end are inclusive 16-bit addresses; decimal and 0x-prefixed\n"
            "hexadecimal are accepted.  'validate' compares a file byte-for-byte\n"
            "with the live radio and never writes to the radio.\n"
            "\n"
            "This is experimental reverse-engineering software. It has been tested\n"
            "on the TK-840; related models or firmware revisions may differ.\n"
            "\n",
            prog, prog, prog, prog);
    print_regions();
    fprintf(stderr,
            "\nAliases: rom/maskrom=bootrom, firmware/prog=program,\n"
            "         channel/codeplug=channels, registers/regs=sfr\n"
            "\n"
            "Program dumps (8000-E5FF), including manual exact-range dumps,\n"
            "also print the Kenwood 16-bit firmware checksum,\n"
            "CRC-16/CCITT-FALSE, and SHA-256. The Kenwood checksum is only a\n"
            "16-bit byte-sum/firmware identifier, not a cryptographic check.\n"
            "\n"
            "SAFETY:\n"
            "  * SFR reads (FF00-FFFF) may have hardware side effects or touch\n"
            "    undefined registers. The sfr region remains available for deliberate\n"
            "    reverse-engineering use, but it is potentially unsafe.\n"
            "  * RAM (FE00-FEFF) is live working memory and may change while read.\n"
            "  * Unmapped addresses may return open-bus/meaningless values.\n"
            "  * 'validate' is read-only: it reads the radio and compares; it never\n"
            "    writes the supplied file to the radio.\n"
            "\n"
            "Examples:\n"
            "  %s /dev/ttyUSB0 bootrom bootrom.bin\n"
            "  %s /dev/ttyUSB0 program firmware.bin\n"
            "  %s /dev/ttyUSB0 channels codeplug.bin\n"
            "  %s /dev/ttyUSB0 0x8000 0xe5ff firmware.bin\n"
            "  %s /dev/ttyUSB0 validate program firmware.bin\n"
            "  %s /dev/ttyUSB0 validate channels codeplug.bin\n",
            prog, prog, prog, prog, prog, prog);
}

static int open_radio(const char *device, char ident[8])
{
    int fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror(device);
        return -1;
    }
    if (enter_program_mode(fd, ident) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int dump_range(int fd, uint32_t start, uint32_t end, FILE *out,
                      struct checksums *sum, int do_sum)
{
    uint32_t first_block = start & ~(uint32_t)(BLOCK_SIZE - 1);
    uint32_t last_block  = end   & ~(uint32_t)(BLOCK_SIZE - 1);
    uint32_t addr;
    uint64_t written = 0;
    uint64_t expected = (uint64_t)end - start + 1;

    fprintf(stderr,
            "Requested %04X-%04X (%llu bytes); reading 0x80-byte blocks %04X-%04X\n",
            (unsigned)start, (unsigned)end,
            (unsigned long long)expected,
            (unsigned)first_block, (unsigned)last_block);

    for (addr = first_block; ; addr += BLOCK_SIZE) {
        uint8_t data[BLOCK_SIZE];
        uint32_t copy_start, copy_end;
        size_t offset, count;

        fprintf(stderr, "\rReading %04X-%04X", (unsigned)addr,
                (unsigned)(addr + BLOCK_SIZE - 1));
        fflush(stderr);

        if (read_block(fd, (uint16_t)addr, data) < 0) {
            fprintf(stderr, "\nRead failed at address %04X\n", (unsigned)addr);
            return -1;
        }

        copy_start = start > addr ? start : addr;
        copy_end = end < addr + BLOCK_SIZE - 1 ? end : addr + BLOCK_SIZE - 1;
        offset = (size_t)(copy_start - addr);
        count = (size_t)(copy_end - copy_start + 1);

        if (fwrite(data + offset, 1, count, out) != count) {
            fprintf(stderr, "\n");
            perror("writing output file");
            return -1;
        }
        if (do_sum)
            checksums_update(sum, data + offset, count);
        written += count;

        if (addr == last_block)
            break;
    }

    fprintf(stderr, "\nDumped %llu bytes\n", (unsigned long long)written);
    if (written != expected) {
        fprintf(stderr, "internal error: expected %llu bytes, wrote %llu\n",
                (unsigned long long)expected,
                (unsigned long long)written);
        return -1;
    }
    return 0;
}

static int get_file_size(FILE *f, uint64_t *size)
{
    struct stat st;
    if (fstat(fileno(f), &st) < 0)
        return -1;
    if (st.st_size < 0) {
        errno = EINVAL;
        return -1;
    }
    *size = (uint64_t)st.st_size;
    return 0;
}

static int validate_range(int fd, uint32_t start, uint32_t end, FILE *in,
                          struct checksums *radio_sum,
                          struct checksums *file_sum,
                          int do_sum)
{
    uint32_t first_block = start & ~(uint32_t)(BLOCK_SIZE - 1);
    uint32_t last_block  = end   & ~(uint32_t)(BLOCK_SIZE - 1);
    uint32_t addr;
    uint64_t compared = 0;
    uint64_t mismatches = 0;
    uint64_t expected = (uint64_t)end - start + 1;
    unsigned shown = 0;

    fprintf(stderr,
            "Validating %04X-%04X (%llu bytes); reading 0x80-byte blocks %04X-%04X\n",
            (unsigned)start, (unsigned)end,
            (unsigned long long)expected,
            (unsigned)first_block, (unsigned)last_block);

    for (addr = first_block; ; addr += BLOCK_SIZE) {
        uint8_t radio_data[BLOCK_SIZE];
        uint8_t file_data[BLOCK_SIZE];
        uint32_t copy_start, copy_end;
        size_t offset, count, i;

        fprintf(stderr, "\rComparing %04X-%04X", (unsigned)addr,
                (unsigned)(addr + BLOCK_SIZE - 1));
        fflush(stderr);

        if (read_block(fd, (uint16_t)addr, radio_data) < 0) {
            fprintf(stderr, "\nRead failed at address %04X\n", (unsigned)addr);
            return -1;
        }

        copy_start = start > addr ? start : addr;
        copy_end = end < addr + BLOCK_SIZE - 1 ? end : addr + BLOCK_SIZE - 1;
        offset = (size_t)(copy_start - addr);
        count = (size_t)(copy_end - copy_start + 1);

        if (fread(file_data, 1, count, in) != count) {
            fprintf(stderr, "\nUnexpected short read from validation file\n");
            return -1;
        }

        if (do_sum) {
            checksums_update(radio_sum, radio_data + offset, count);
            checksums_update(file_sum, file_data, count);
        }

        for (i = 0; i < count; ++i) {
            if (radio_data[offset + i] != file_data[i]) {
                ++mismatches;
                if (shown < MAX_MISMATCHES_SHOWN) {
                    if (shown == 0)
                        fprintf(stderr, "\n");
                    fprintf(stderr,
                            "Mismatch at %04X: radio=%02X file=%02X\n",
                            (unsigned)(copy_start + i),
                            radio_data[offset + i], file_data[i]);
                    ++shown;
                }
            }
        }
        compared += count;

        if (addr == last_block)
            break;
    }

    fprintf(stderr, "\nCompared %llu bytes\n", (unsigned long long)compared);
    if (mismatches == 0) {
        fprintf(stderr, "VALIDATE: exact match\n");
        return 0;
    }

    if (mismatches > shown)
        fprintf(stderr, "... %llu additional mismatch(es) not shown\n",
                (unsigned long long)(mismatches - shown));
    fprintf(stderr, "VALIDATE: %llu byte mismatch(es)\n",
            (unsigned long long)mismatches);
    return EXIT_MISMATCH;
}

int main(int argc, char **argv)
{
    const char *device;
    const char *file_path;
    const struct region *region = NULL;
    uint32_t start = 0, end = 0;
    uint64_t expected;
    int validate = 0;
    int fd = -1;
    FILE *file = NULL;
    char ident[8];
    int entered = 0;
    int rc = EXIT_FAILURE;
    int do_program_checksums;
    struct checksums radio_sum, file_sum;

    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
                      !strcmp(argv[1], "help"))) {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (argc < 4 || argc > 6) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    device = argv[1];

    if (!strcmp(argv[2], "validate")) {
        validate = 1;
        if (argc == 5) {
            region = find_region(argv[3]);
            if (!region) {
                fprintf(stderr, "Unknown region '%s'\n\n", argv[3]);
                print_regions();
                return EXIT_FAILURE;
            }
            start = region->start;
            end = region->end;
            file_path = argv[4];
        } else if (argc == 6) {
            if (parse_addr(argv[3], &start) < 0 || parse_addr(argv[4], &end) < 0) {
                fprintf(stderr, "start/end must be 16-bit decimal or 0x-prefixed hex addresses\n");
                return EXIT_FAILURE;
            }
            file_path = argv[5];
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        if (argc == 4) {
            region = find_region(argv[2]);
            if (!region) {
                fprintf(stderr, "Unknown region '%s'\n\n", argv[2]);
                print_regions();
                return EXIT_FAILURE;
            }
            start = region->start;
            end = region->end;
            file_path = argv[3];
        } else if (argc == 5) {
            if (parse_addr(argv[2], &start) < 0 || parse_addr(argv[3], &end) < 0) {
                fprintf(stderr, "start/end must be 16-bit decimal or 0x-prefixed hex addresses\n");
                return EXIT_FAILURE;
            }
            file_path = argv[4];
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (start > end) {
        fprintf(stderr, "start address must be <= end address\n");
        return EXIT_FAILURE;
    }

    warn_selected_range(start, end);

    expected = (uint64_t)end - start + 1;
    do_program_checksums = is_program_range(start, end);

    if (validate) {
        uint64_t file_size;
        file = fopen(file_path, "rb");
        if (!file) {
            perror(file_path);
            return EXIT_FAILURE;
        }
        if (get_file_size(file, &file_size) < 0) {
            perror("getting validation file size");
            fclose(file);
            return EXIT_FAILURE;
        }
        if (file_size != expected) {
            fprintf(stderr,
                    "Validation file size is %llu bytes; selected range requires %llu bytes\n",
                    (unsigned long long)file_size,
                    (unsigned long long)expected);
            fclose(file);
            return EXIT_FAILURE;
        }
    } else {
        file = fopen(file_path, "wb");
        if (!file) {
            perror(file_path);
            return EXIT_FAILURE;
        }
    }

    if (do_program_checksums) {
        checksums_init(&radio_sum);
        if (validate)
            checksums_init(&file_sum);
    }

    fd = open_radio(device, ident);
    if (fd < 0)
        goto done;
    entered = 1;

    {
        const char *id_status = classify_radio_id(ident);
        fprintf(stderr, "Radio ID: %s\n", ident);
        if (id_status)
            fprintf(stderr, "Radio ID status: %s\n", id_status);
        else
            fprintf(stderr,
                    "WARNING: unrecognized radio identification '%s'.\n"
                    "         This utility will continue, but the memory map/protocol\n"
                    "         may not match this radio.\n",
                    ident);

        if (strlen(ident) == 7 && ident[6] == 'Y')
            fprintf(stderr,
                    "WARNING: radio ID indicates the password-protection flag is set;\n"
                    "         read behavior may differ from an unprotected radio.\n");
    }
    if (region)
        fprintf(stderr, "Region: %s (%04X-%04X, %s)\n",
                region->name, (unsigned)start, (unsigned)end, region->description);

    if (validate) {
        int vr = validate_range(fd, start, end, file,
                                &radio_sum, &file_sum,
                                do_program_checksums);
        if (do_program_checksums) {
            print_checksums("Radio program", &radio_sum);
            print_checksums("File program", &file_sum);
        }
        if (vr == 0)
            rc = EXIT_SUCCESS;
        else if (vr == EXIT_MISMATCH)
            rc = EXIT_MISMATCH;
        else
            rc = EXIT_FAILURE;
    } else {
        if (dump_range(fd, start, end, file, &radio_sum, do_program_checksums) < 0)
            goto done;
        fprintf(stderr, "Output: %s\n", file_path);
        if (do_program_checksums)
            print_checksums("Program", &radio_sum);
        rc = EXIT_SUCCESS;
    }

done:
    if (entered)
        exit_program_mode(fd);
    if (file && fclose(file) != 0 && rc == EXIT_SUCCESS) {
        perror("closing file");
        rc = EXIT_FAILURE;
    }
    if (fd >= 0)
        close(fd);

    /* Remove an incomplete dump on failure.  Never unlink validation input. */
    if (!validate && rc != EXIT_SUCCESS)
        unlink(file_path);

    return rc;
}
