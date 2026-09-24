/*
 * tk941patch.c - Data-driven firmware patcher for Kenwood TK-941.
 * Copyright 2026 by Dave "WormFood" <kenwood-tk-x4x@wormfood.net>
 *
 * Derived from tk840upload.c transport/recovery-loader work.
 *
 * Design goals:
 *   - Patch definitions are data, not hard-coded flashing logic.
 *   - Every mutation has an exact expected preimage (old bytes -> new bytes).
 *   - SHA-256 is the strongest known-revision identity; sum16 is retained as a Kenwood revision/checksum field.
 *   - Can patch a raw 0x6600-byte firmware file offline.
 *   - Can patch a live radio, writing only changed 64-byte AT29C256 pages.
 *   - Live writes force and verify the E66C.2 recovery interlock unless
 *     --force-unsafe is explicitly supplied.
 *   - Full firmware readback verification is required after live writes.
 *
 * External patch file format (TKPATCH v2):
 *
 *   [patch example-name]
 *   description = Human-readable description
 *   model = M941B1
 *   sum16 = B5EC
 *   sha256 = 1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818
 *   replace 0x9C6E : 28 9D 9C 71 9E 0A 2D F0 09 1A 20 3A 22 01 14 18 -> 28 9A DE 83 29 60 03 00 88 E8 59 24 01 5D 03 9F
 *
 * CPU addresses are used, not file offsets. Multiple replace lines are
 * allowed. Immediately following before/after lines are exact context guards
 * for the preceding replacement. Old and new byte counts must match.
 * Comments begin with # or ;.
 *
 * Build:
 *   gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -o tk941patch tk941patch.c
 */

#define _DEFAULT_SOURCE

#include <ctype.h>
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
#define BLOCK_SIZE 0x80u
#define FLASH_PAGE_SIZE 0x40u
#define HEX_DATA_SIZE 0x10u
#define TIMEOUT_MS 1500

#define PROGRAM_START  0x8000u
#define PROGRAM_END    0xE5FFu
#define PROGRAM_SIZE   (PROGRAM_END - PROGRAM_START + 1u)
#define CODEPLUG_START 0xE600u

#define RECOVERY_ADDR   0xE66Cu
#define RECOVERY_MASK   0x04u

#define PASSWORD_ADDR   0xE670u
#define PASSWORD_LENGTH 10u

#define FIRMWARE_SIGNATURE_ADDR   0xE580u
#define FIRMWARE_SIGNATURE_OFFSET (FIRMWARE_SIGNATURE_ADDR - PROGRAM_START)
#define FIRMWARE_SIGNATURE        "KENWOOD"
#define FIRMWARE_SIGNATURE_LEN    7u

#define MAX_NAME 80
#define MAX_DESC 256
#define MAX_MODEL 16
#define MAX_HUNK_BYTES 256
#define MAX_PATCH_FILES 32
#define MAX_CONTEXT_BYTES 64
#define SHA256_HEX_LEN 64
#define TK941PATCH_VERSION "5"

struct hunk {
    uint16_t addr;
    uint16_t resolved_addr;
    int resolved;
    int source_was_new;
    size_t len;
    uint8_t old_bytes[MAX_HUNK_BYTES];
    uint8_t new_bytes[MAX_HUNK_BYTES];
    size_t before_len;
    uint8_t before[MAX_CONTEXT_BYTES];
    size_t after_len;
    uint8_t after[MAX_CONTEXT_BYTES];
    struct hunk *next;
};

struct patch {
    char name[MAX_NAME];
    char description[MAX_DESC];
    char model[MAX_MODEL];
    int has_sum16;
    uint16_t sum16;
    int has_sha256;
    char sha256[SHA256_HEX_LEN + 1];
    int builtin;
    struct hunk *hunks;
    struct hunk *hunks_tail;
    struct patch *next;
};

struct options {
    int dry_run;
    int force_unsafe;
    int relaxed_identity;
    const char *offline_model;
    const char *backup_path;
    const char *learn_path;
};

static struct patch *patches;
static struct patch *patches_tail;

struct sha256_ctx { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t used; };
static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void sha256_block(struct sha256_ctx *c, const uint8_t b[64]) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    uint32_t w[64],a,d,e,f,g,h,i,t1,t2,bb,cc;
    for (i=0;i<16;i++) w[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
    for (;i<64;i++) { uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3); uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    a=c->s[0]; bb=c->s[1]; cc=c->s[2]; d=c->s[3]; e=c->s[4]; f=c->s[5]; g=c->s[6]; h=c->s[7];
    for (i=0;i<64;i++) { uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25); uint32_t ch=(e&f)^((~e)&g); t1=h+S1+ch+k[i]+w[i]; uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22); uint32_t maj=(a&bb)^(a&cc)^(bb&cc); t2=S0+maj; h=g; g=f; f=e; e=d+t1; d=cc; cc=bb; bb=a; a=t1+t2; }
    c->s[0]+=a;c->s[1]+=bb;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(struct sha256_ctx *c) { static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; memcpy(c->s,iv,sizeof(iv)); c->bits=0;c->used=0; }
static void sha256_update(struct sha256_ctx *c,const void *vp,size_t n){const uint8_t*p=vp;c->bits+=(uint64_t)n*8;while(n){size_t q=64-c->used;if(q>n)q=n;memcpy(c->buf+c->used,p,q);c->used+=q;p+=q;n-=q;if(c->used==64){sha256_block(c,c->buf);c->used=0;}}}
static void sha256_final(struct sha256_ctx*c,uint8_t out[32]){size_t i;c->buf[c->used++]=0x80;if(c->used>56){while(c->used<64)c->buf[c->used++]=0;sha256_block(c,c->buf);c->used=0;}while(c->used<56)c->buf[c->used++]=0;for(i=0;i<8;i++)c->buf[63-i]=(uint8_t)(c->bits>>(i*8));sha256_block(c,c->buf);for(i=0;i<8;i++){out[i*4]=(uint8_t)(c->s[i]>>24);out[i*4+1]=(uint8_t)(c->s[i]>>16);out[i*4+2]=(uint8_t)(c->s[i]>>8);out[i*4+3]=(uint8_t)c->s[i];}}
static void sha256_hex(const uint8_t *p,size_t n,char out[65]){static const char h[]="0123456789abcdef";struct sha256_ctx c;uint8_t d[32];size_t i;sha256_init(&c);sha256_update(&c,p,n);sha256_final(&c,d);for(i=0;i<32;i++){out[i*2]=h[d[i]>>4];out[i*2+1]=h[d[i]&15];}out[64]=0;}
static int valid_sha256_hex(const char*s){size_t i;if(strlen(s)!=64)return 0;for(i=0;i<64;i++)if(!isxdigit((unsigned char)s[i]))return 0;return 1;}

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
    tio.c_cflag |= CS8 | CSTOPB | CLOCAL | CREAD;
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

    if (write_all(fd, req, sizeof(req)) < 0 || read_exact(fd, &first, 1) < 0)
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
    if (write_all(fd, &ack, 1) < 0 || read_exact(fd, &ack, 1) < 0)
        return -1;
    if (ack != ACK) {
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
        errno = EPERM;
        return -1;
    }
    if (write_all(fd, hdr, sizeof(hdr)) < 0 ||
        write_all(fd, data, BLOCK_SIZE) < 0 || read_exact(fd, &ack, 1) < 0)
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
    if (read_block(fd, CODEPLUG_START, block) < 0)
        return -1;
    msg[0] = 0x04;
    memcpy(msg + 1, block + off, PASSWORD_LENGTH);
    if (write_all(fd, msg, sizeof(msg)) < 0 || read_exact(fd, &ack, 1) < 0)
        return -1;
    if (ack != ACK) {
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
    return authenticate_if_needed(fd, ident);
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

static uint16_t byte_sum16(const uint8_t *p, size_t len)
{
    uint32_t s = 0;
    size_t i;
    for (i = 0; i < len; ++i)
        s += p[i];
    return (uint16_t)s;
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
    fclose(f);
    if (n != expected) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int write_file_exact(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (!f) {
        perror(path);
        return -1;
    }
    n = fwrite(buf, 1, len, f);
    if (fclose(f) != 0 || n != len) {
        perror(path);
        return -1;
    }
    return 0;
}

static int write_backup_exact(const char *path, const uint8_t *buf, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno == EEXIST)
            fprintf(stderr, "Backup file already exists; refusing to overwrite: %s\n", path);
        else
            perror(path);
        return -1;
    }
    if (write_all(fd, buf, len) < 0) {
        perror(path);
        close(fd);
        unlink(path);
        return -1;
    }
    if (close(fd) < 0) {
        perror(path);
        unlink(path);
        return -1;
    }
    return 0;
}

static char *trim(char *s)
{
    char *e;
    while (isspace((unsigned char)*s))
        ++s;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static struct patch *find_patch(const char *name)
{
    struct patch *p;
    for (p = patches; p; p = p->next)
        if (!strcmp(p->name, name))
            return p;
    return NULL;
}

static struct patch *new_patch(const char *name, int builtin)
{
    struct patch *p;
    if (!name || !*name || strlen(name) >= MAX_NAME) {
        errno = EINVAL;
        return NULL;
    }
    if (find_patch(name)) {
        fprintf(stderr, "duplicate patch name: %s\n", name);
        errno = EEXIST;
        return NULL;
    }
    p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    strcpy(p->name, name);
    p->builtin = builtin;
    if (!patches)
        patches = p;
    else
        patches_tail->next = p;
    patches_tail = p;
    return p;
}

static int add_hunk(struct patch *p, uint16_t addr,
                    const uint8_t *oldb, const uint8_t *newb, size_t len)
{
    struct hunk *h;
    if (!p || !len || len > MAX_HUNK_BYTES || addr < PROGRAM_START ||
        (uint32_t)addr + len - 1u > PROGRAM_END) {
        errno = EINVAL;
        return -1;
    }
    h = calloc(1, sizeof(*h));
    if (!h)
        return -1;
    h->addr = addr;
    h->len = len;
    memcpy(h->old_bytes, oldb, len);
    memcpy(h->new_bytes, newb, len);
    if (!p->hunks)
        p->hunks = h;
    else
        p->hunks_tail->next = h;
    p->hunks_tail = h;
    return 0;
}

static int parse_hex_bytes(char *s, uint8_t *out, size_t *out_len)
{
    size_t n = 0;
    char *tok;
    for (tok = strtok(s, " \t"); tok; tok = strtok(NULL, " \t")) {
        char *end;
        unsigned long v;
        if (n >= MAX_HUNK_BYTES)
            return -1;
        errno = 0;
        v = strtoul(tok, &end, 16);
        if (errno || *end || v > 0xFF)
            return -1;
        out[n++] = (uint8_t)v;
    }
    if (!n)
        return -1;
    *out_len = n;
    return 0;
}

static int parse_replace_line(struct patch *p, char *line, const char *path, unsigned lineno)
{
    char *colon, *arrow, *left, *right, *end;
    unsigned long addr;
    uint8_t oldb[MAX_HUNK_BYTES], newb[MAX_HUNK_BYTES];
    size_t oldn, newn;

    line = trim(line + 7); /* after 'replace' */
    colon = strchr(line, ':');
    if (!colon) {
        fprintf(stderr, "%s:%u: replace line needs ':'\n", path, lineno);
        return -1;
    }
    *colon = '\0';
    errno = 0;
    addr = strtoul(trim(line), &end, 0);
    if (errno || *trim(end) || addr > 0xFFFF) {
        fprintf(stderr, "%s:%u: invalid CPU address\n", path, lineno);
        return -1;
    }
    left = colon + 1;
    arrow = strstr(left, "->");
    if (!arrow) {
        fprintf(stderr, "%s:%u: replace line needs '->'\n", path, lineno);
        return -1;
    }
    *arrow = '\0';
    right = arrow + 2;
    left = trim(left);
    right = trim(right);
    if (parse_hex_bytes(left, oldb, &oldn) < 0 ||
        parse_hex_bytes(right, newb, &newn) < 0 || oldn != newn) {
        fprintf(stderr, "%s:%u: invalid/mismatched byte lists\n", path, lineno);
        return -1;
    }
    if (add_hunk(p, (uint16_t)addr, oldb, newb, oldn) < 0) {
        fprintf(stderr, "%s:%u: invalid patch range\n", path, lineno);
        return -1;
    }
    return 0;
}

static int set_context_line(struct hunk *h, const char *which, char *val, const char *path, unsigned lineno) {
    uint8_t tmp[MAX_HUNK_BYTES]; size_t n=0; char copy[1024];
    if (!h) { fprintf(stderr, "%s:%u: %s requires a preceding replace line\n", path, lineno, which); return -1; }
    if (strlen(val)>=sizeof(copy)) return -1;
    strcpy(copy,val);
    if (parse_hex_bytes(copy,tmp,&n)<0 || n>MAX_CONTEXT_BYTES) { fprintf(stderr, "%s:%u: invalid %s byte list\n", path, lineno, which); return -1; }
    if (!strcmp(which,"before")) { h->before_len=n; memcpy(h->before,tmp,n); }
    else { h->after_len=n; memcpy(h->after,tmp,n); }
    return 0;
}

static int load_patch_file(const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[2048];
    unsigned lineno = 0;
    struct patch *cur = NULL;
    struct hunk *last_hunk = NULL;
    if (!f) {
        perror(path);
        return -1;
    }
    while (fgets(buf, sizeof(buf), f)) {
        char *s, *eq;
        ++lineno;
        s = trim(buf);
        if (!*s || *s == '#' || *s == ';')
            continue;
        if (*s == '[') {
            char *rbr = strchr(s, ']');
            char *name;
            if (!rbr || rbr[1]) {
                fprintf(stderr, "%s:%u: malformed section\n", path, lineno);
                goto fail;
            }
            *rbr = '\0';
            if (strncmp(s + 1, "patch ", 6)) {
                fprintf(stderr, "%s:%u: expected [patch name]\n", path, lineno);
                goto fail;
            }
            name = trim(s + 7);
            cur = new_patch(name, 0);
            last_hunk = NULL;
            if (!cur)
                goto fail;
            continue;
        }
        if (!cur) {
            fprintf(stderr, "%s:%u: setting outside [patch ...] section\n", path, lineno);
            goto fail;
        }
        if (!strncmp(s, "replace", 7) && isspace((unsigned char)s[7])) {
            if (parse_replace_line(cur, s, path, lineno) < 0)
                goto fail;
            last_hunk = cur->hunks_tail;
            continue;
        }
        eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "%s:%u: unknown line\n", path, lineno);
            goto fail;
        }
        *eq = '\0';
        {
            char *key = trim(s);
            char *val = trim(eq + 1);
            if (!strcmp(key, "description")) {
                if (strlen(val) >= sizeof(cur->description))
                    goto fail;
                strcpy(cur->description, val);
            } else if (!strcmp(key, "model")) {
                if (strlen(val) >= sizeof(cur->model))
                    goto fail;
                strcpy(cur->model, val);
            } else if (!strcmp(key, "before")) {
                if (set_context_line(last_hunk, "before", val, path, lineno) < 0) goto fail;
            } else if (!strcmp(key, "after")) {
                if (set_context_line(last_hunk, "after", val, path, lineno) < 0) goto fail;
            } else if (!strcmp(key, "sha256")) {
                size_t j;
                if (!valid_sha256_hex(val)) { fprintf(stderr, "%s:%u: invalid sha256\n", path, lineno); goto fail; }
                for (j=0;j<64;j++) cur->sha256[j]=(char)tolower((unsigned char)val[j]);
                cur->sha256[64]=0; cur->has_sha256=1;
            } else if (!strcmp(key, "sum16")) {
                char *end;
                unsigned long v;
                errno = 0;
                v = strtoul(val, &end, 16);
                if (errno || *trim(end) || v > 0xFFFF) {
                    fprintf(stderr, "%s:%u: invalid sum16\n", path, lineno);
                    goto fail;
                }
                cur->sum16 = (uint16_t)v;
                cur->has_sum16 = 1;
            } else {
                fprintf(stderr, "%s:%u: unknown key '%s'\n", path, lineno, key);
                goto fail;
            }
        }
    }
    fclose(f);
    return 0;
fail:
    fclose(f);
    return -1;
}

static void add_builtin_patches(void)
{
    struct patch *p; struct hunk *h;
    static const uint8_t old_txfield[] = {0x28,0x9D,0x9C,0x71,0x9E,0x0A,0x2D,0xF0,0x09,0x1A,0x20,0x3A,0x22,0x01,0x14,0x18};
    static const uint8_t new_txfield[] = {0x28,0x9A,0xDE,0x83,0x29,0x60,0x03,0x00,0x88,0xE8,0x59,0x24,0x01,0x5D,0x03,0x9F};
    static const uint8_t tx_before[] = {0x00,0x28,0x59,0x9B,0x28,0x46,0x9D,0x56};
    static const uint8_t tx_after[]  = {0x08,0xA0,0xDA,0x05,0x2D,0xE0,0xFB,0x14};
    static const uint8_t oldoff[] = {0x2D,0xC0,0xFD}; static const uint8_t newoff[] = {0x2D,0x20,0x02};
    static const uint8_t off_before[] = {0x1A,0x20,0x3A,0x22,0x01,0x14,0x18,0x08,0xA0,0xDA,0x05,0x2D,0xE0,0xFB,0x14,0x03};
    static const uint8_t off_after[] = {0x1A,0x20,0x82,0x05,0x3A,0x22,0x01,0x14,0x03,0x3A,0x22,0x00,0x28,0x59,0x9B,0x28};
    const uint16_t offaddr[3]={0x9AB6,0x9C58,0x9C87}; int i;
    p=new_patch("tk941-txfield-b5ec",1); if(!p){perror("adding builtin patch");exit(1);} strcpy(p->description,"TK-941 B5EC: use the stored channel TX-frequency word directly"); strcpy(p->model,"M941B1"); p->has_sum16=1;p->sum16=0xB5EC;p->has_sha256=1;strcpy(p->sha256,"1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818");
    if(add_hunk(p,0x9C6E,old_txfield,new_txfield,sizeof(old_txfield))<0){perror("adding builtin hunks");exit(1);} h=p->hunks_tail;h->before_len=sizeof(tx_before);memcpy(h->before,tx_before,sizeof(tx_before));h->after_len=sizeof(tx_after);memcpy(h->after,tx_after,sizeof(tx_after));
    p=new_patch("tk941-25mhz-b5ec",1); if(!p){perror("adding builtin patch");exit(1);} strcpy(p->description,"TK-941 B5EC: change stock fixed split from 39 MHz to 25 MHz; conventional TX is bypassed when TX-field patch is active"); strcpy(p->model,"M941B1");p->has_sum16=1;p->sum16=0xB5EC;p->has_sha256=1;strcpy(p->sha256,"1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818");
    for(i=0;i<3;i++){if(add_hunk(p,offaddr[i],oldoff,newoff,sizeof(oldoff))<0){perror("adding builtin hunks");exit(1);}h=p->hunks_tail;h->before_len=sizeof(off_before);memcpy(h->before,off_before,sizeof(off_before));h->after_len=sizeof(off_after);memcpy(h->after,off_after,sizeof(off_after));}
}

static void print_hex_bytes(FILE *f,const uint8_t*p,size_t n){size_t i;for(i=0;i<n;i++)fprintf(f,"%02X%s",p[i],i+1==n?"":" ");}
static void list_patches(void){struct patch*p;for(p=patches;p;p=p->next){unsigned n=0;struct hunk*h;for(h=p->hunks;h;h=h->next)n++;printf("%-24s %s\n",p->name,p->builtin?"[built-in]":"[external]");if(*p->description)printf("  %s\n",p->description);printf("  model=%s sum16=",*p->model?p->model:"*");if(p->has_sum16)printf("%04X",p->sum16);else printf("*");printf(" sha256=%s hunks=%u\n",p->has_sha256?p->sha256:"*",n);}}
static void show_patch(const struct patch*p){const struct hunk*h;printf("Patch: %s%s\n",p->name,p->builtin?" [built-in]":"");if(*p->description)printf("Description: %s\n",p->description);printf("Model: %s\n",*p->model?p->model:"*");printf("Source sum16: %s",p->has_sum16?"":"*\n");if(p->has_sum16)printf("%04X\n",p->sum16);printf("Source SHA-256: %s\n",p->has_sha256?p->sha256:"*");for(h=p->hunks;h;h=h->next){printf("  %04X: ",h->addr);print_hex_bytes(stdout,h->old_bytes,h->len);printf(" -> ");print_hex_bytes(stdout,h->new_bytes,h->len);printf("\n");if(h->before_len){printf("    before: ");print_hex_bytes(stdout,h->before,h->before_len);printf("\n");}if(h->after_len){printf("    after:  ");print_hex_bytes(stdout,h->after,h->after_len);printf("\n");}}}

static int model_matches(const char *want, const char *actual)
{
    size_t n;
    if (!want || !*want || !strcmp(want, "*"))
        return 1;
    if (!actual || !*actual)
        return 0;
    n = strlen(want);
    return !strncmp(want, actual, n);
}

static int hunk_context_matches(const struct hunk*h,const uint8_t*image,uint16_t addr){size_t o=addr-PROGRAM_START;if(h->before_len){if(o<h->before_len||memcmp(image+o-h->before_len,h->before,h->before_len))return 0;}if(h->after_len){if(o+h->len+h->after_len>PROGRAM_SIZE||memcmp(image+o+h->len,h->after,h->after_len))return 0;}return 1;}
static int hunk_bytes_state(const struct hunk*h,const uint8_t*image,uint16_t addr){const uint8_t*p=image+(addr-PROGRAM_START);if(!memcmp(p,h->old_bytes,h->len))return 1;if(!memcmp(p,h->new_bytes,h->len))return 2;return 0;}
static int same_signature(const struct hunk*a,const struct hunk*b){return a->len==b->len&&a->before_len==b->before_len&&a->after_len==b->after_len&&!memcmp(a->old_bytes,b->old_bytes,a->len)&&!memcmp(a->new_bytes,b->new_bytes,a->len)&&!memcmp(a->before,b->before,a->before_len)&&!memcmp(a->after,b->after,a->after_len);}
static int resolve_patch(struct patch*p,const uint8_t*image,const char*sha,const struct options*opt,int verbose){struct hunk*h,*g;int sha_known=p->has_sha256&&!strcmp(p->sha256,sha);for(h=p->hunks;h;h=h->next){h->resolved=0;h->source_was_new=0;}
 for(h=p->hunks;h;h=h->next){if(h->resolved)continue;int st=hunk_bytes_state(h,image,h->addr);
  if(st&&hunk_context_matches(h,image,h->addr)){h->resolved=1;h->resolved_addr=h->addr;h->source_was_new=(st==2);continue;}
  /*
   * Reversal safety: if the exact replacement bytes are already present at
   * the patch's declared address, accept that address even when surrounding
   * context changed because another known patch touched nearby bytes. We do
   * not use this relaxation to APPLY a patch, and relocated matches still
   * require exact context.
   */
  if(st==2){h->resolved=1;h->resolved_addr=h->addr;h->source_was_new=1;if(verbose)fprintf(stderr,"Patch %s: patched bytes found at declared address %04X; context differs, treating as reversible.\n",p->name,h->addr);continue;}
  {uint16_t cand[MAX_HUNK_BYTES];int cst[MAX_HUNK_BYTES];size_t nc=0,o;for(o=0;o+h->len<=PROGRAM_SIZE;o++){uint16_t a=(uint16_t)(PROGRAM_START+o);int s=hunk_bytes_state(h,image,a);if(!s)continue;if((h->before_len||h->after_len)&&!hunk_context_matches(h,image,a))continue;if(nc<MAX_HUNK_BYTES){cand[nc]=a;cst[nc]=s;}nc++;}
   if(nc==1){h->resolved=1;h->resolved_addr=cand[0];h->source_was_new=(cst[0]==2);if(verbose)fprintf(stderr,"Patch %s: contextual pattern relocated %04X -> %04X\n",p->name,h->addr,h->resolved_addr);continue;}
   if(nc>1){size_t group=0,seen=0;for(g=p->hunks;g;g=g->next)if(same_signature(h,g)){group++;}if(nc==group&&group>1){for(g=p->hunks;g;g=g->next)if(same_signature(h,g)){if(!g->resolved){g->resolved=1;g->resolved_addr=cand[seen];g->source_was_new=(cst[seen]==2);}seen++;}continue;}}
   if(opt->relaxed_identity){nc=0;for(o=0;o+h->len<=PROGRAM_SIZE;o++){uint16_t a=(uint16_t)(PROGRAM_START+o);int s=hunk_bytes_state(h,image,a);if(!s)continue;if(nc<MAX_HUNK_BYTES){cand[nc]=a;cst[nc]=s;}nc++;}if(nc==1){h->resolved=1;h->resolved_addr=cand[0];h->source_was_new=(cst[0]==2);if(verbose)fprintf(stderr,"WARNING: %s using unique byte-only match at %04X\n",p->name,h->resolved_addr);continue;}}
   if (verbose) {
       fprintf(stderr, "Patch %s: could not uniquely resolve hunk originally at %04X%s.\n",
               p->name, h->addr, sha_known ? " on known SHA-256" : "");
   }
   return -1;}}
 return 0;}
static int patch_apply_one(struct patch*p,uint8_t*image,const uint8_t*source_image,const char*model,uint16_t source_sum,const char*source_sha,const struct options*opt,size_t*changed_bytes){struct hunk*h;size_t local=0,total=0,nold=0,nnew=0;if(*p->model&&model&&*model&&!model_matches(p->model,model)){fprintf(stderr,"Patch %s requires model %s; current model is %s.\n",p->name,p->model,model);return -1;}if(*p->model&&(!model||!*model)&&!opt->relaxed_identity){fprintf(stderr,"Patch %s requires model %s; use --model for offline patching.\n",p->name,p->model);return -1;}
 if(p->has_sha256&&!strcmp(p->sha256,source_sha))fprintf(stderr,"Patch %s: SHA-256 identifies known source firmware.\n",p->name);else if(p->has_sha256)fprintf(stderr,"Patch %s: source SHA-256 differs from the original definition; resolving exact patch state/context.\n",p->name);
 if(resolve_patch(p,source_image,source_sha,opt,1)<0)return -1;
 if(p->has_sum16&&source_sum!=p->sum16&&p->has_sha256&&!strcmp(p->sha256,source_sha)){fprintf(stderr,"Patch %s: internal identity conflict (SHA matches, sum16 differs).\n",p->name);return -1;}
 for(h=p->hunks;h;h=h->next){total++;if(h->source_was_new)nnew++;else nold++;}
 if(nold&&nnew){fprintf(stderr,"Patch %s is only partially applied (%zu original hunk%s, %zu patched hunk%s); refusing to guess whether to apply or revert.\n",p->name,nold,nold==1?"":"s",nnew,nnew==1?"":"s");return -1;}
 if(nnew==total){
  fprintf(stderr,"Patch %s is already applied; reverting it.\n",p->name);
  for(h=p->hunks;h;h=h->next){uint8_t*cur=image+(h->resolved_addr-PROGRAM_START);fprintf(stderr,"Patch %-24s %04X: reverting %zu byte(s)\n",p->name,h->resolved_addr,h->len);{size_t i;for(i=0;i<h->len;i++)if(cur[i]!=h->old_bytes[i])local++;}memcpy(cur,h->old_bytes,h->len);}
 }else{
  for(h=p->hunks;h;h=h->next){uint8_t*cur=image+(h->resolved_addr-PROGRAM_START);fprintf(stderr,"Patch %-24s %04X: applying %zu byte(s)\n",p->name,h->resolved_addr,h->len);{size_t i;for(i=0;i<h->len;i++)if(cur[i]!=h->new_bytes[i])local++;}memcpy(cur,h->new_bytes,h->len);}
 }
 *changed_bytes+=local;return 0;}
static int apply_selected_patches(uint8_t*image,const char*model,uint16_t source_sum,const char*source_sha,const struct options*opt,char**names,int count,size_t*changed_bytes){int i;uint8_t*source_image=malloc(PROGRAM_SIZE);if(!source_image){perror("malloc");return -1;}memcpy(source_image,image,PROGRAM_SIZE);*changed_bytes=0;for(i=0;i<count;i++){struct patch*p=find_patch(names[i]);if(!p){fprintf(stderr,"Unknown patch: %s\n",names[i]);free(source_image);return -1;}if(patch_apply_one(p,image,source_image,model,source_sum,source_sha,opt,changed_bytes)<0){free(source_image);return -1;}}free(source_image);return 0;}

/* Return 1 if this patch has at least one unapplied hunk, 2 if it is already
 * fully applied, or 0 if it cannot be safely resolved against this image. */
static int patch_def_equivalent(const struct patch *a, const struct patch *b)
{
    const struct hunk *ha = a->hunks, *hb = b->hunks;
    if (strcmp(a->model, b->model) || a->has_sum16 != b->has_sum16 ||
        (a->has_sum16 && a->sum16 != b->sum16) ||
        a->has_sha256 != b->has_sha256 ||
        (a->has_sha256 && strcmp(a->sha256, b->sha256)))
        return 0;
    while (ha && hb) {
        if (ha->addr != hb->addr || ha->len != hb->len ||
            ha->before_len != hb->before_len || ha->after_len != hb->after_len ||
            memcmp(ha->old_bytes, hb->old_bytes, ha->len) ||
            memcmp(ha->new_bytes, hb->new_bytes, ha->len) ||
            memcmp(ha->before, hb->before, ha->before_len) ||
            memcmp(ha->after, hb->after, ha->after_len))
            return 0;
        ha = ha->next;
        hb = hb->next;
    }
    return !ha && !hb;
}

static int patch_candidate_status(struct patch *p, const uint8_t *image,
                                  const char *model, uint16_t source_sum,
                                  const char *source_sha,
                                  const struct options *opt)
{
    struct hunk *h;
    size_t nold = 0, nnew = 0, total = 0;

    if (*p->model && model && *model && !model_matches(p->model, model))
        return 0;
    if (*p->model && (!model || !*model) && !opt->relaxed_identity)
        return 0;
    if (resolve_patch(p, image, source_sha, opt, 0) < 0)
        return 0;
    if (p->has_sum16 && source_sum != p->sum16 && p->has_sha256 &&
        !strcmp(p->sha256, source_sha))
        return 0;
    for (h = p->hunks; h; h = h->next) {
        ++total;
        if (h->source_was_new)
            ++nnew;
        else
            ++nold;
    }
    if (nold == total)
        return 1; /* Apply. */
    if (nnew == total)
        return 2; /* Revert. */
    return 3;     /* Partial/mixed state; do not auto-select. */
}

static int select_patches_interactive(const uint8_t *image, const char *model,
                                      uint16_t source_sum, const char *source_sha,
                                      const struct options *opt,
                                      char ***names_out, int *count_out)
{
    struct patch *p;
    struct patch **choices = NULL;
    int *choice_status = NULL;
    char **names = NULL;
    size_t total = 0, nchoices = 0, npartial = 0, i;
    char line[512];

    for (p = patches; p; p = p->next)
        ++total;
    choices = calloc(total ? total : 1, sizeof(*choices));
    choice_status = calloc(total ? total : 1, sizeof(*choice_status));
    if (!choices || !choice_status) {
        perror("calloc");
        free(choices);
        free(choice_status);
        return -1;
    }

    for (p = patches; p; p = p->next) {
        int st = patch_candidate_status(p, image, model, source_sum, source_sha, opt);
        if (st == 1 || st == 2) {
            size_t j;
            int duplicate = 0;
            for (j = 0; j < nchoices; ++j) {
                if (patch_def_equivalent(choices[j], p)) {
                    /* If an external file repeats a built-in definition, show
                     * the external name because that is what the user loaded. */
                    if (choices[j]->builtin && !p->builtin)
                        choices[j] = p;
                    choice_status[j] = st;
                    duplicate = 1;
                    break;
                }
            }
            if (!duplicate) {
                choices[nchoices] = p;
                choice_status[nchoices] = st;
                ++nchoices;
            }
        } else if (st == 3) {
            ++npartial;
        }
    }

    fprintf(stderr, "\nPatch actions available for this firmware:\n");
    for (i = 0; i < nchoices; ++i) {
        p = choices[i];
        if (choice_status[i] == 2) {
            fprintf(stderr, "  %zu) REVERT %s  [patch bytes already present]\n",
                    i + 1, p->name);
        } else {
            fprintf(stderr, "  %zu) APPLY  %s%s\n", i + 1, p->name,
                    (p->has_sha256 && !strcmp(p->sha256, source_sha)) ?
                    "  [known SHA-256]" : "  [exact context match]");
        }
        if (*p->description)
            fprintf(stderr, "     %s\n", p->description);
    }
    if (npartial)
        fprintf(stderr, "  (%zu matching definition%s in a partial/mixed state; not selectable automatically)\n",
                npartial, npartial == 1 ? " is" : "s are");

    if (!nchoices) {
        if (npartial)
            fprintf(stderr, "No unambiguous apply/revert action is available.\n");
        else
            fprintf(stderr, "No loaded patch safely matches this firmware.\n");
        free(choice_status);
        free(choices);
        return -1;
    }

    for (;;) {
        if (nchoices == 1)
            fprintf(stderr, "Select action [1] (Enter=1, q=quit): ");
        else
            fprintf(stderr, "Select action(s) (e.g. 1,3 or a=all, q=quit): ");
        fflush(stderr);
        if (!fgets(line, sizeof(line), stdin)) {
            fprintf(stderr, "\nInput cancelled.\n");
            free(choice_status);
            free(choices);
            return -1;
        }
        {
            char *s = trim(line);
            size_t selected = 0;
            unsigned char *seen;
            char *tok, *save = NULL;

            if (!*s && nchoices == 1)
                s = "1";
            if (!strcasecmp(s, "q") || !strcasecmp(s, "quit")) {
                free(choice_status);
                free(choices);
                return -1;
            }
            names = calloc(nchoices, sizeof(*names));
            seen = calloc(nchoices, 1);
            if (!names || !seen) {
                perror("calloc");
                free(names); free(seen); free(choice_status); free(choices);
                return -1;
            }
            if (!strcasecmp(s, "a") || !strcasecmp(s, "all")) {
                for (i = 0; i < nchoices; ++i)
                    names[selected++] = choices[i]->name;
            } else {
                for (tok = strtok_r(s, ", \t", &save); tok;
                     tok = strtok_r(NULL, ", \t", &save)) {
                    char *end;
                    long v = strtol(tok, &end, 10);
                    if (*end || v < 1 || (size_t)v > nchoices) {
                        selected = 0;
                        break;
                    }
                    if (!seen[v - 1]) {
                        seen[v - 1] = 1;
                        names[selected++] = choices[v - 1]->name;
                    }
                }
            }
            free(seen);
            if (selected) {
                *names_out = names;
                *count_out = (int)selected;
                fprintf(stderr, "Selected:");
                for (i = 0; i < selected; ++i)
                    fprintf(stderr, " %s%s", names[i], i + 1 == selected ? "\n" : ",");
                free(choice_status);
                free(choices);
                return 0;
            }
            free(names);
            names = NULL;
            fprintf(stderr, "Invalid selection.\n");
        }
    }
}

static int is_patch_file_arg(const char *s)
{
    size_t n = strlen(s);
    return n >= 8 && !strcasecmp(s + n - 8, ".tkpatch");
}

/* Positional .tkpatch files are loaded automatically. Remaining arguments are
 * explicit patch names. This makes `radio DEV file.tkpatch` the natural UI. */
static int process_patch_arguments(char **args, int argc,
                                   char ***names_out, int *count_out)
{
    char **names;
    int i, n = 0;

    names = calloc(argc ? (size_t)argc : 1, sizeof(*names));
    if (!names) {
        perror("calloc");
        return -1;
    }
    for (i = 0; i < argc; ++i) {
        if (is_patch_file_arg(args[i])) {
            if (load_patch_file(args[i]) < 0) {
                free(names);
                return -1;
            }
            fprintf(stderr, "Loaded patch file: %s\n", args[i]);
        } else {
            names[n++] = args[i];
        }
    }
    *names_out = names;
    *count_out = n;
    return 0;
}

static int write_learn_file(const char*path,const uint8_t*source,const char*model,uint16_t sum,const char*sha,char**names,int count){FILE*f;int i;if(!path)return 0;f=fopen(path,"wx");if(!f){perror(path);return -1;}fprintf(f,"# TKPATCH learned definitions generated by tk941patch\n# Review before distributing.\n\n");for(i=0;i<count;i++){struct patch*p=find_patch(names[i]);struct hunk*h;if(!p){fclose(f);return -1;}for(h=p->hunks;h;h=h->next)if(h->source_was_new){fprintf(stderr,"Cannot learn %s: source already contains patched bytes at %04X.\n",p->name,h->resolved_addr);fclose(f);unlink(path);return -1;}fprintf(f,"[patch %s-%04x]\n",p->name,sum);fprintf(f,"description = Learned from %s at sum16 %04X\n",p->name,sum);if(model&&*model)fprintf(f,"model = %.6s\n",model);fprintf(f,"sum16 = %04X\nsha256 = %s\n",sum,sha);for(h=p->hunks;h;h=h->next){size_t o=h->resolved_addr-PROGRAM_START,bn=o<8?o:8,an=(PROGRAM_SIZE-(o+h->len))<8?(PROGRAM_SIZE-(o+h->len)):8;fprintf(f,"replace 0x%04X : ",h->resolved_addr);print_hex_bytes(f,h->old_bytes,h->len);fprintf(f," -> ");print_hex_bytes(f,h->new_bytes,h->len);fprintf(f,"\n");if(bn){fprintf(f,"before = ");print_hex_bytes(f,source+o-bn,bn);fprintf(f,"\n");}if(an){fprintf(f,"after = ");print_hex_bytes(f,source+o+h->len,an);fprintf(f,"\n");}}fprintf(f,"\n");}if(fclose(f)!=0){perror(path);return -1;}fprintf(stderr,"Wrote learned patch definitions: %s\n",path);return 0;}

static size_t mismatch_count(const uint8_t *a, const uint8_t *b, size_t len,
                             uint32_t base, int show)
{
    size_t i, n = 0;
    unsigned shown = 0;
    for (i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            ++n;
            if (show && shown < 16) {
                fprintf(stderr, "  mismatch %04X: radio=%02X target=%02X\n",
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
    if (block[in_block] & RECOVERY_MASK) {
        fprintf(stderr, "Recovery interlock already enabled: E66C=%02X.\n", block[in_block]);
        return 0;
    }
    if (dry_run) {
        fprintf(stderr, "DRY RUN: would set E66C bit 2 before firmware programming.\n");
        return 0;
    }
    memcpy(target, block, sizeof(target));
    target[in_block] |= RECOVERY_MASK;
    fprintf(stderr, "Setting recovery interlock E66C bit 2: %02X -> %02X\n",
            block[in_block], target[in_block]);
    if (write_block(fd, CODEPLUG_START, target) < 0 ||
        verify_block_exact(fd, CODEPLUG_START, target) < 0)
        return -1;
    fprintf(stderr, "Recovery interlock verified ON.\n");
    return 0;
}

static char hex_digit(unsigned v)
{
    return "0123456789ABCDEF"[v & 0x0F];
}

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
    out[pos++] = ':';
    PUTHEX(len); sum = (uint8_t)(sum + len);
    PUTHEX(rel_addr >> 8); sum = (uint8_t)(sum + (rel_addr >> 8));
    PUTHEX(rel_addr); sum = (uint8_t)(sum + rel_addr);
    PUTHEX(0x00);
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
        size_t len = make_hex_record(rec, sizeof(rec), (uint16_t)(rel_page + n),
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
            fprintf(stderr, "Could not re-enter PROGRAM mode for verification (%s).\n",
                    strerror(errno));
            if (prompt_enter(
                    "Power the radio normally (release SYSTEM UP), then press Enter to retry: ") < 0)
                return -1;
        }
    }
    return -1;
}

static int program_target_image(int fd, const uint8_t *current, const uint8_t *target,
                                const struct options *opt, char ident[8])
{
    uint8_t *verify = malloc(PROGRAM_SIZE);
    uint8_t *changed = calloc(PROGRAM_SIZE / FLASH_PAGE_SIZE, 1);
    size_t page, changed_pages = 0, changed_bytes;
    int program_active = 1;
    int rc = -1;

    if (!verify || !changed) {
        perror("malloc");
        goto out;
    }
    changed_bytes = mismatch_count(current, target, PROGRAM_SIZE, PROGRAM_START, 0);
    for (page = 0; page < PROGRAM_SIZE / FLASH_PAGE_SIZE; ++page) {
        if (memcmp(current + page * FLASH_PAGE_SIZE,
                   target + page * FLASH_PAGE_SIZE, FLASH_PAGE_SIZE) != 0) {
            changed[page] = 1;
            ++changed_pages;
        }
    }
    fprintf(stderr, "Firmware differences: %zu byte(s), %zu changed 64-byte page(s).\n",
            changed_bytes, changed_pages);
    if (!changed_pages) {
        fprintf(stderr, "Nothing to write.\n");
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
        rc = 0;
        goto out;
    }

    if (!opt->force_unsafe) {
        if (force_recovery_flag_in_session(fd, 0) < 0) {
            fprintf(stderr, "Cannot establish/verify recovery interlock; aborting.\n");
            goto out;
        }
    } else {
        fprintf(stderr, "*** --force-unsafe: recovery interlock is not being enforced. ***\n");
    }

    fprintf(stderr,
            "\nFirmware patching now requires the resident recovery loader.\n"
            "Hold SYSTEM UP while powering on until the display shows PROG.\n");
    exit_program_mode(fd);
    program_active = 0;
    if (prompt_enter("Enter PROG/recovery mode, then press Enter: ") < 0)
        goto out;
    if (set_serial(fd, B9600) < 0)
        goto out;
    assert_modem_lines(fd);
    tcflush(fd, TCIFLUSH);
    usleep(100000);

    /* First byte selects the ASCII-HEX path and is discarded by the loader. */
    if (write_all(fd, "\r", 1) < 0 || tcdrain(fd) < 0)
        goto out;
    usleep(20000);

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
                goto out;
            }
        }
        fprintf(stderr, "\n");
    }
    if (write_all(fd, ":00\r\n", 5) < 0 || tcdrain(fd) < 0)
        goto out;
    fprintf(stderr, "Firmware patch stream complete.\n");

    if (prompt_enter(
            "Release SYSTEM UP and power-cycle normally if needed. Press Enter for verification: ") < 0)
        goto out;
    if (reopen_program_for_verify(fd, ident) < 0) {
        fprintf(stderr, "VERIFY FAILED: could not re-enter PROGRAM mode.\n");
        goto out;
    }
    program_active = 1;
    if (read_region(fd, PROGRAM_START, PROGRAM_SIZE, verify, "verify") < 0)
        goto out;
    if (memcmp(verify, target, PROGRAM_SIZE) != 0) {
        fprintf(stderr, "FIRMWARE VERIFY FAILED.\n");
        mismatch_count(verify, target, PROGRAM_SIZE, PROGRAM_START, 1);
        goto out;
    }
    fprintf(stderr, "Firmware verified byte-for-byte. sum16=%04X\n",
            byte_sum16(verify, PROGRAM_SIZE));
    rc = 0;
out:
    if (rc != 0 && program_active)
        exit_program_mode(fd);
    free(verify);
    free(changed);
    return rc;
}

static int offline_mode(const char *inpath, const char *outpath,
                        char **names, int count, const struct options *opt)
{
    uint8_t *source = malloc(PROGRAM_SIZE);
    uint8_t *target = malloc(PROGRAM_SIZE);
    uint16_t sum;
    char sha[65];
    size_t changed;
    char **menu_names = NULL;
    char **selected_names = names;
    int selected_count = count;
    int rc = -1;
    if (!source || !target) {
        perror("malloc");
        goto out;
    }
    if (!strcmp(inpath, outpath) && !opt->force_unsafe) {
        fprintf(stderr, "Refusing in-place firmware overwrite. Use a separate output file.\n");
        goto out;
    }
    if (read_file_exact(inpath, source, PROGRAM_SIZE) < 0)
        goto out;
    memcpy(target, source, PROGRAM_SIZE);
    sum = byte_sum16(source, PROGRAM_SIZE); sha256_hex(source, PROGRAM_SIZE, sha);
    fprintf(stderr, "Input firmware sum16: %04X\nInput firmware SHA-256: %s\n", sum, sha);
    if (selected_count == 0) {
        if (select_patches_interactive(source, opt->offline_model, sum, sha, opt,
                                       &menu_names, &selected_count) < 0)
            goto out;
        selected_names = menu_names;
    }
    if (apply_selected_patches(target, opt->offline_model, sum, sha, opt,
                               selected_names, selected_count, &changed) < 0)
        goto out;
    if (memcmp(target + FIRMWARE_SIGNATURE_OFFSET, FIRMWARE_SIGNATURE,
               FIRMWARE_SIGNATURE_LEN) != 0 && !opt->force_unsafe) {
        fprintf(stderr, "Refusing output: patched image lacks KENWOOD signature at E580.\n");
        goto out;
    }
    fprintf(stderr, "Patch-byte writes requested: %zu\n", changed);
    fprintf(stderr, "Output firmware sum16: %04X\n", byte_sum16(target, PROGRAM_SIZE));
    fprintf(stderr, "Actual changed bytes: %zu\n",
            mismatch_count(source, target, PROGRAM_SIZE, PROGRAM_START, 0));
    { char outsha[65]; sha256_hex(target, PROGRAM_SIZE, outsha); fprintf(stderr, "Output firmware SHA-256: %s\n", outsha); }
    if (opt->learn_path && write_learn_file(opt->learn_path, source, opt->offline_model, sum, sha, selected_names, selected_count) < 0) goto out;
    if (opt->dry_run) {
        fprintf(stderr, "DRY RUN: output file not written.\n");
        rc = 0;
        goto out;
    }
    if (write_file_exact(outpath, target, PROGRAM_SIZE) < 0)
        goto out;
    fprintf(stderr, "Wrote patched firmware: %s\n", outpath);
    rc = 0;
out:
    free(menu_names);
    free(source);
    free(target);
    return rc;
}

static int radio_mode(const char *device, char **names, int count,
                      const struct options *opt)
{
    uint8_t *current = malloc(PROGRAM_SIZE);
    uint8_t *target = malloc(PROGRAM_SIZE);
    uint16_t sum;
    char sha[65];
    size_t changed;
    char **menu_names = NULL;
    char **selected_names = names;
    int selected_count = count;
    int fd = -1, rc = -1;
    char ident[8];

    if (!current || !target) {
        perror("malloc");
        goto out;
    }
    fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror(device);
        goto out;
    }
    if (enter_program_mode(fd, ident) < 0) {
        perror("entering PROGRAM mode");
        goto out;
    }
    if (read_region(fd, PROGRAM_START, PROGRAM_SIZE, current, "firmware") < 0)
        goto out_exit;
    memcpy(target, current, PROGRAM_SIZE);
    sum = byte_sum16(current, PROGRAM_SIZE); sha256_hex(current, PROGRAM_SIZE, sha);
    fprintf(stderr, "Live firmware sum16: %04X\nLive firmware SHA-256: %s\n", sum, sha);

    if (selected_count == 0) {
        if (select_patches_interactive(current, ident, sum, sha, opt,
                                       &menu_names, &selected_count) < 0)
            goto out_exit;
        selected_names = menu_names;
    }

    if (opt->backup_path) {
        if (write_backup_exact(opt->backup_path, current, PROGRAM_SIZE) < 0)
            goto out_exit;
        fprintf(stderr, "Saved pre-patch firmware backup: %s\n", opt->backup_path);
    }

    if (apply_selected_patches(target, ident, sum, sha, opt, selected_names, selected_count, &changed) < 0)
        goto out_exit;
    if (memcmp(target + FIRMWARE_SIGNATURE_OFFSET, FIRMWARE_SIGNATURE,
               FIRMWARE_SIGNATURE_LEN) != 0 && !opt->force_unsafe) {
        fprintf(stderr, "Refusing write: patched target lacks KENWOOD signature at E580.\n");
        goto out_exit;
    }
    fprintf(stderr, "Patch-byte writes requested: %zu\n", changed);
    fprintf(stderr, "Target firmware sum16: %04X\n", byte_sum16(target, PROGRAM_SIZE));
    { char outsha[65]; sha256_hex(target, PROGRAM_SIZE, outsha); fprintf(stderr, "Target firmware SHA-256: %s\n", outsha); }
    if (opt->learn_path && write_learn_file(opt->learn_path, current, ident, sum, sha, selected_names, selected_count) < 0) goto out_exit;

    rc = program_target_image(fd, current, target, opt, ident);
    if (rc == 0)
        exit_program_mode(fd);
    goto out;

out_exit:
    exit_program_mode(fd);
out:
    if (fd >= 0)
        close(fd);
    free(menu_names);
    free(current);
    free(target);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [options] list\n"
        "  %s [options] show <patch>\n"
        "  %s [options] file <input.bin> <output.bin> [patch|file.tkpatch ...]\n"
        "  %s [options] radio <serial-device> [patch|file.tkpatch ...]\n"
        "\n"
        "Options:\n"
        "  --patch-file FILE       load additional TKPATCH definitions (repeatable)\n"
        "                          A positional *.tkpatch file is also loaded automatically.\n"
        "                          With no explicit patch names, a matching-patch menu is shown.\n"
        "  --dry-run               compare/apply in memory only; never write radio/file\n"
        "  --model MODEL           offline model identity, e.g. M941B1\n"
        "  --backup FILE           save live pre-patch firmware before radio write\n"
        "  --learn FILE            write revision-specific TKPATCH definitions\n"
        "  --relaxed-identity      permit unique byte-only fallback if exact context cannot match\n"
        "  --force-unsafe          do not enforce recovery bit or KENWOOD signature\n"
        "  --version               show tk941patch version\n"
        "\n"
        "Patch file example:\n"
        "  [patch my-patch]\n"
        "  description = Example\n"
        "  model = M941B1\n"
        "  sum16 = B5EC\n"
        "  sha256 = 1005ad3f16f127a8bd8613fd3168a2f8285ceedebb378b6c9f9f87786cb61818\n"
        "  replace 0x9C6E : 28 9D 9C 71 9E 0A 2D F0 09 1A 20 3A 22 01 14 18 -> 28 9A DE 83 29 60 03 00 88 E8 59 24 01 5D 03 9F\n"
        "  before = 00 28 59 9B 28 46 9D 56\n"
        "  after = 08 A0 DA 05 2D E0 FB 14\n"
        "\n"
        "All firmware images are raw 0x6600-byte 8000-E5FF images.\n",
        prog, prog, prog, prog);
}

static void free_patches(void)
{
    struct patch *p = patches;
    while (p) {
        struct patch *pn = p->next;
        struct hunk *h = p->hunks;
        while (h) {
            struct hunk *hn = h->next;
            free(h);
            h = hn;
        }
        free(p);
        p = pn;
    }
}

int main(int argc, char **argv)
{
    struct options opt;
    const char *patch_files[MAX_PATCH_FILES];
    int patch_file_count = 0;
    int argi = 1, i, rc = 1;
    const char *cmd;

    memset(&opt, 0, sizeof(opt));
    add_builtin_patches();

    while (argi < argc && !strncmp(argv[argi], "--", 2)) {
        if (!strcmp(argv[argi], "--patch-file")) {
            if (++argi >= argc || patch_file_count >= MAX_PATCH_FILES) {
                usage(argv[0]);
                goto out;
            }
            patch_files[patch_file_count++] = argv[argi++];
        } else if (!strcmp(argv[argi], "--dry-run")) {
            opt.dry_run = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--force-unsafe")) {
            opt.force_unsafe = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--relaxed-identity")) {
            opt.relaxed_identity = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--model")) {
            if (++argi >= argc) {
                usage(argv[0]);
                goto out;
            }
            opt.offline_model = argv[argi++];
        } else if (!strcmp(argv[argi], "--backup")) {
            if (++argi >= argc) { usage(argv[0]); goto out; }
            opt.backup_path = argv[argi++];
        } else if (!strcmp(argv[argi], "--learn")) {
            if (++argi >= argc) { usage(argv[0]); goto out; }
            opt.learn_path = argv[argi++];
        } else if (!strcmp(argv[argi], "--version")) {
            printf("tk941patch v%s\n", TK941PATCH_VERSION);
            rc = 0;
            goto out;
        } else if (!strcmp(argv[argi], "--help")) {
            usage(argv[0]);
            rc = 0;
            goto out;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[argi]);
            usage(argv[0]);
            goto out;
        }
    }

    for (i = 0; i < patch_file_count; ++i) {
        if (load_patch_file(patch_files[i]) < 0)
            goto out;
    }
    if (argi >= argc) {
        usage(argv[0]);
        goto out;
    }
    cmd = argv[argi++];

    if (!strcmp(cmd, "list")) {
        if (argi != argc) {
            usage(argv[0]);
            goto out;
        }
        list_patches();
        rc = 0;
    } else if (!strcmp(cmd, "show")) {
        struct patch *p;
        if (argc - argi != 1) {
            usage(argv[0]);
            goto out;
        }
        p = find_patch(argv[argi]);
        if (!p) {
            fprintf(stderr, "Unknown patch: %s\n", argv[argi]);
            goto out;
        }
        show_patch(p);
        rc = 0;
    } else if (!strcmp(cmd, "file")) {
        char **names = NULL;
        int name_count = 0;
        if (argc - argi < 2) {
            usage(argv[0]);
            goto out;
        }
        if (process_patch_arguments(argv + argi + 2, argc - (argi + 2),
                                    &names, &name_count) < 0)
            goto out;
        rc = offline_mode(argv[argi], argv[argi + 1], names,
                          name_count, &opt) == 0 ? 0 : 1;
        free(names);
    } else if (!strcmp(cmd, "radio")) {
        char **names = NULL;
        int name_count = 0;
        if (argc - argi < 1) {
            usage(argv[0]);
            goto out;
        }
        if (process_patch_arguments(argv + argi + 1, argc - (argi + 1),
                                    &names, &name_count) < 0)
            goto out;
        rc = radio_mode(argv[argi], names, name_count, &opt) == 0 ? 0 : 1;
        free(names);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
    }
out:
    free_patches();
    return rc;
}
