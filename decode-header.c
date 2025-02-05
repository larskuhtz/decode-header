#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#if __APPLE__
#include <sys/types.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif

/* ************************************************************************** */
/* NOTES */

/*
 * This code requires endian.h to provide the functions le64toh, le32toh, and
 * le16toh
 */

/* ************************************************************************** */
/* Hex Formatting */

/*
 * Precondition: len(outbuf) >= len(inbuf * 2 + 1)
 *
 * Input is not expected to be null terminated.
 *
 * Output is null terminated. The number of written characters other than the
 * terminating null bytes is returned.
 */
int hex(char *buf, const unsigned char *inbuf, size_t len)
{
    char *p = buf;
    for (size_t i = 0; i < len; ++i) {
        p += sprintf(p, "%02x", inbuf[i]);
    }
    *p = 0;
    return p - buf;
}

/* Input is not expected to be null terminated.
 */
void print_hex(const unsigned char *inbuf, size_t len)
{
    char *buf = (char *) malloc(len * 2 + 1);
    hex(buf, inbuf, len);
    printf("0x%s", buf);
    free(buf);
}

/* inspired by https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
 *
 * TODO: this is highly unsafe
 *
 */
int decode_hex(unsigned char *dst, const char *src, size_t srclen)
{
    // 54
    static const unsigned char TBL[] = {
        0,1,2,3,4,5,6,7,8,9,58,59,60,61,62,63,
        64,10,11,12,13,14,15,71,72,73,74,75,76,77,78,79,
        80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,
        96,10,11,12,13,14,15
    };

    static const unsigned char *LOOKUP = TBL - 48;

    const char* end = src + srclen;
    unsigned char *p = dst;

    /* empty string */
    if(*src == 0) {
        return 0;
    }

    while(src < end) {
        unsigned char a = LOOKUP[(size_t) *(src++)];
        if (a > 15) {
            fprintf(stderr, "invalid hex character: %u\n", *(src-1));
            exit(1);
        }
        unsigned char b = LOOKUP[(size_t) *(src++)];
        if (b > 15) {
            fprintf(stderr, "invalid hex character: %u\n", *(src-1));
            exit(1);
        }
        *(p++) = (a << 4) | b;
    }

    return p - dst;
}

/* ************************************************************************** */
/* Base64 decoder
 *
 * https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 */

static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int isbase64(char c) {
    return c && strchr(table, c) != NULL;
}

char value(char c)
{
    const char *p = strchr(table, c);
    if(p) {
        return p-table;
    } else {
        return 0;
    }
}

/* Doesn't include terminating 0 byte in the result! */

int decode_base64Url(unsigned char *dest, const char *src, int srclen)
{
    /* empty string */
    if(*src == 0) {
        return 0;
    }

    unsigned char *p = dest;
    do {

        char a = value(src[0]);
        char b = value(src[1]);
        char c = value(src[2]);
        char d = value(src[3]);
        *p++ = (a << 2) | (b >> 4);
        *p++ = (b << 4) | (c >> 2);
        *p++ = (c << 6) | d;
        if(!isbase64(src[1])) {
            p -= 2;
            break;
        } else if(!isbase64(src[2])) {
            p -= 2;
            break;
        } else if(!isbase64(src[3])) {
            p--;
            break;
        }
        src += 4;
        while(*src && (*src == 13 || *src == 10)) src++;

    } while(srclen-= 4);

    return p-dest;
    }

size_t b64_encoded_size(size_t inlen)
{
    size_t ret;
    size_t rem = inlen % 3 == 0 ? 0 : 3 - (inlen % 3);
    ret = inlen;
    ret += rem;
    ret /= 3;
    ret *= 4;
    ret -= rem;
    return ret;
}

// https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
//
// Result includes terminating null character. The returned length
// of the result doesn't count the terminating null character.
//
// dst must be of b64_encoded_size(srclen) + 1
//
size_t b64_encode(char* dst, const unsigned char *src, size_t srclen)
{
    size_t elen;
    size_t i;
    size_t j;
    size_t v;

    if (src == NULL) {
        return 0;
    }

    elen = b64_encoded_size(srclen);
    dst[elen] = '\0';

    for (i=0, j=0; i<srclen; i+=3, j+=4) {
        v = src[i];
        v = i+1 < srclen ? v << 8 | src[i+1] : v << 8;
        v = i+2 < srclen ? v << 8 | src[i+2] : v << 8;

        dst[j] = table[(v >> 18) & 0x3F];
        dst[j+1] = table[(v >> 12) & 0x3F];
        if (i+1 < srclen) {
            dst[j+2] = table[(v >> 6) & 0x3F];
        }
        if (i+2 < srclen) {
            dst[j+3] = table[v & 0x3F];
        }
    }

    return elen;
}

/* ************************************************************************** */
/* Constants and Auxiliary Types */

// Only chainweb versions with a graph of this degree are supported
//
# define CHAINWEB_DEGREE 3

enum chainweb_version {
    development = 1,
    mainnet01 = 5,
    testnet04 = 7,
    testnet05 = 9,
    unknown
};

typedef struct { unsigned char merkle_hash[32]; } MerkleHash;
typedef struct { unsigned char pow_nat[32]; } PowNat;

struct adjacent_parent {
    uint32_t chain;
    MerkleHash parent;
} __attribute__((__packed__));

typedef struct{
    uint16_t degree;
    struct adjacent_parent adjacent_parents[CHAINWEB_DEGREE];
}  __attribute__((__packed__)) Adjacents;

/* ************************************************************************** */
/* Header Binary Format */

#define MERKLE_HASH_SIZE 32
#define POWNAT_SIZE 32

#define FLAGS_SIZE 8
#define TIME_SIZE 8
#define PARENT_SIZE (MERKLE_HASH_SIZE)
#define ADJACENTS_SIZE (2 + (CHAINWEB_DEGREE) * ((MERKLE_HASH_SIZE) + 4))
#define TARGET_SIZE (POWNAT_SIZE)
#define PAYLOAD_SIZE (MERKLE_HASH_SIZE)
#define CHAIN_SIZE 4
#define WEIGHT_SIZE (POWNAT_SIZE)
#define HEIGHT_SIZE 8
#define VERSION_SIZE 4
#define EPOCH_SIZE (TIME_SIZE)
#define NONCE_SIZE 8
#define HASH_SIZE (MERKLE_HASH_SIZE)

#define FLAGS_OFFSET 0
#define TIME_OFFSET ((FLAGS_OFFSET) + (FLAGS_SIZE))
#define PARENT_OFFSET ((TIME_OFFSET) + (TIME_SIZE))
#define ADJACENTS_OFFSET ((PARENT_OFFSET) + (PARENT_SIZE))
#define TARGET_OFFSET ((ADJACENTS_OFFSET) + (ADJACENTS_SIZE))
#define PAYLOAD_OFFSET ((TARGET_OFFSET) + (TARGET_SIZE))
#define CHAIN_OFFSET ((PAYLOAD_OFFSET) + (PAYLOAD_SIZE))
#define WEIGHT_OFFSET ((CHAIN_OFFSET) + (CHAIN_SIZE))
#define HEIGHT_OFFSET ((WEIGHT_OFFSET) + (WEIGHT_SIZE))
#define VERSION_OFFSET ((HEIGHT_OFFSET) + (HEIGHT_SIZE))
#define EPOCH_OFFSET ((VERSION_OFFSET) + (VERSION_SIZE))
#define NONCE_OFFSET ((EPOCH_OFFSET) + (EPOCH_SIZE))
#define HASH_OFFSET ((NONCE_OFFSET) + (NONCE_SIZE))

#define WORK_HEADER_SIZE (HASH_OFFSET)
#define HEADER_SIZE ((HASH_OFFSET) + (HASH_SIZE))

typedef struct { unsigned char work_header_bytes[WORK_HEADER_SIZE]; } WorkHeaderBytes;
typedef struct { unsigned char header_bytes[HEADER_SIZE]; } HeaderBytes;

// reserved. Always 0x0
//
static uint64_t read_flags(const HeaderBytes *hdr)
{
    return le64toh(*(uint64_t *)(hdr->header_bytes + FLAGS_OFFSET));
}

// time in microseconds since POSIX epoch
//
static uint64_t read_time(const HeaderBytes *hdr)
{
    return le64toh(*(uint64_t *)(hdr->header_bytes + TIME_OFFSET));
}

static void read_parent(const HeaderBytes *hdr, MerkleHash *ret)
{
    assert(PARENT_SIZE == sizeof(MerkleHash));
    memcpy(ret->merkle_hash, hdr->header_bytes + PARENT_OFFSET, PARENT_SIZE);
}

static void read_adjacents(const HeaderBytes *hdr, Adjacents *ret)
{
    assert(ADJACENTS_SIZE == sizeof(Adjacents));
    assert(*((uint16_t *) (hdr->header_bytes + ADJACENTS_OFFSET)) == CHAINWEB_DEGREE);

    memcpy(ret->adjacent_parents, hdr->header_bytes + ADJACENTS_OFFSET + 2, ADJACENTS_SIZE - 2);
}

static void read_target(const HeaderBytes *hdr, PowNat *ret)
{
    assert(TARGET_SIZE == sizeof(PowNat));
    memcpy(ret->pow_nat, hdr->header_bytes + TARGET_OFFSET, TARGET_SIZE);
}

static void read_payload(const HeaderBytes *hdr, MerkleHash *ret)
{
    assert(PAYLOAD_SIZE == sizeof(MerkleHash));
    memcpy(ret->merkle_hash, hdr->header_bytes + PAYLOAD_OFFSET, PAYLOAD_SIZE);
}

static uint16_t read_chain(const HeaderBytes *hdr)
{
    return le64toh(*(uint16_t *)(hdr->header_bytes + CHAIN_OFFSET));
}

static void read_weight(const HeaderBytes *hdr, PowNat* ret)
{
    assert(WEIGHT_SIZE == sizeof(PowNat));
    memcpy(ret->pow_nat, hdr->header_bytes + WEIGHT_OFFSET, WEIGHT_SIZE);
}

static int read_height(const HeaderBytes *hdr)
{
    return (int) (le64toh(*(int64_t *)(hdr->header_bytes + HEIGHT_OFFSET)));
}

static enum chainweb_version read_version(const HeaderBytes *hdr)
{
    uint32_t code = le32toh(*(uint32_t *)(hdr->header_bytes + VERSION_OFFSET));
    switch (code) {
    case 0x00000001:
        return development;
    case 0x00000005:
        return mainnet01;
    case 0x00000007:
        return testnet04;
    case 0x00000009:
        return testnet05;
    default:
        fprintf(stderr, "warning: unknown chainweb version code %d\n", code);
        return unknown;
    }
}

static uint64_t read_epoch(const HeaderBytes *hdr)
{
    return le64toh(*(uint64_t *) (hdr->header_bytes + EPOCH_OFFSET));
}

// These are plain bits. No byte order conversion is performed
//
static uint64_t read_nonce(const HeaderBytes *hdr)
{
    return *(uint64_t *)(hdr->header_bytes + NONCE_OFFSET);
}

static void read_hash(const HeaderBytes *hdr, MerkleHash *ret)
{
    assert(HASH_SIZE == sizeof(MerkleHash));
    memcpy(ret->merkle_hash, hdr->header_bytes + HASH_OFFSET, HASH_SIZE);
}

/* ************************************************************************** */
/* Header */

struct header {
    uint64_t flags;
    uint64_t time;                  // 8 required (can be compressed)
    MerkleHash parent;
    Adjacents adjacents;
    PowNat target;                  // 32 (partly optional)
    MerkleHash payload;             // 32 required
    uint16_t chain;
    PowNat weight;
    int height;
    enum chainweb_version version;
    uint64_t epoch;                 // 8 (partly optional)
    uint64_t nonce;                 // 8 required
    MerkleHash hash;
};

// Return new header by value
//
void read_header(const HeaderBytes *bin, struct header *hdr)
{
    hdr->flags = read_flags(bin);
    hdr->time = read_time(bin);
    read_parent(bin, &hdr->parent);
    read_adjacents(bin, &hdr->adjacents);
    read_target(bin, &hdr->target);
    read_payload(bin, &hdr->payload);
    hdr->chain = read_chain(bin);
    read_weight(bin, &hdr->weight);
    hdr->height = read_height(bin);
    hdr->version = read_version(bin);
    hdr->epoch = read_epoch(bin);
    hdr->nonce = read_nonce(bin);
    read_hash(bin, &hdr->hash);
}

/* ************************************************************************** */
/* Work Header (used in mining) */

struct work_header {
    uint64_t flags;
    uint64_t time;                  // 8 required (can be compressed)
    MerkleHash parent;
    Adjacents adjacents;
    PowNat target;                  // 32 (partly optional)
    MerkleHash payload;             // 32 required
    uint16_t chain;
    PowNat weight;
    int height;
    enum chainweb_version version;
    uint64_t epoch;                 // 8 (partly optional)
    uint64_t nonce;                 // 8 required
};


// Return new header by value
//
void read_work_header(const WorkHeaderBytes *wbin, struct work_header *whdr)
{
    const HeaderBytes *bin = (HeaderBytes *) wbin;
    struct work_header *hdr = (struct work_header *) whdr;

    hdr->flags = read_flags(bin);
    hdr->time = read_time(bin);
    read_parent(bin, &hdr->parent);
    read_adjacents(bin, &hdr->adjacents);
    read_target(bin, &hdr->target);
    read_payload(bin, &hdr->payload);
    hdr->chain = read_chain(bin);
    read_weight(bin, &hdr->weight);
    hdr->height = read_height(bin);
    hdr->version = read_version(bin);
    hdr->epoch = read_epoch(bin);
    hdr->nonce = read_nonce(bin);
}

/* ************************************************************************** */
/* Test Data */

const char *test = "AAAAAAAAAAAAJ41tFZYFAMCen1Rev76833pqkLFgepws36zMM522bHJ-d_tA6QHCAwACAAAAfJB-vS9h7ByxNHY19WqM8icji9CcATiXn48uouHAMzsDAAAAUsNRCUkMKQBRDVIv0JLDfDllYNg2QO0EXaWcRfMQ6g0FAAAAdTLm0UrocvMNjjz_TMUbWqpZhuBBht_JoNqZpCliaS___________________________________________5NR9w7CJwD7ydFv8z8Z66ZHkjXT1E9EvVPG6gyxu9_aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAACeNbRWWBQAAAAAAAAAAAEjQDFxwb2bQG3ktfcddm2VdqeXdROAWsa4IHHjXVMW8";
const char *test2 = "rOWwgv-HXe_MFrD8F5YFAEjQDFxwb2bQG3ktfcddm2VdqeXdROAWsa4IHHjXVMW8AwACAAAAIsgjp62lHk0uXgQfu_HZoeuP3udIiwkBlq1hHvXqXCMDAAAAtMyy7k6lrQOsGg2oXh20kOC3zudjwsaL9F5Ogx0XNBoFAAAAGmCgnnxUtn08N8WtL8Gpn3Hg6AKyP4q0W0u3NLZn0Zr__________________________________________9XNmV_vK7Iw9JjG205dregjbsVkFC0FJVmScTR9lO4uAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAFAAAAACeNbRWWBQAAAAAAAAAAAPuQJ1SWQezIwRWKswcaCugmimoQa--9SJodyblZZr7W";
const char *test3 = "AAAAAAAAAAAl1tud5qsFAOBQSuKiBr73-TORcDs31OmVtpF2Z4-1MzQDE15ILxhKAwACAAAAUhGML7d_hi3j3OR4tlhS9bBzj5KGdIrB7PNcRY9JF78DAAAAbLnbvQPhg_CB_fhBfdJHfDJmzwQUru3haQ_60M_txzkFAAAAB3d-ys3TtzENoAAQk1mlkXOnVC5F9HoJe5DKwlCx6uxlrkeW4mCdagJf0xENGK4q2pyfpxrdZfDxWAAAAAAAAJx7jlNRNF0ZZAfB5VpP4RhWzHlL-XHmTnZ_MxZLrAJLAAAAANsDGkvj_awhFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUMAAAAAAAFAAAAwzIqC-arBQBP3XPqijwjArbgFZjh9u_sDX-g_NgiwtlZKL9_OkmQNEgbbn57YmK9";

/* ************************************************************************** */
/* JSON formatting */

int json_version(char *buf, const enum chainweb_version ver) {
    switch (ver) {
    case development:
        return sprintf(buf, "\"development\"");
    case mainnet01:
        return sprintf(buf, "\"mainnet01\"");
    case testnet04:
        return sprintf(buf, "\"testnet04\"");
    case testnet05:
        return sprintf(buf, "\"testnet05\"");
    default:
        return sprintf(buf, "\"unknown\"");
    }
}

/*
 * Output is null terminated. The number of written characters other than the
 * terminating null bytes is returned.
 */
int json_adjacents_hex(char *buf, const Adjacents* adjs)
{
    char *p = buf;

    p += sprintf(p, "{");

    for (size_t i = 0; i < CHAINWEB_DEGREE; ++i) {
        if (i > 0) {
            p += sprintf(p, ",");
        }
        p += sprintf(p, "\"%d\":\"", (adjs->adjacent_parents)[i].chain);
        p += hex(p, (adjs->adjacent_parents)[i].parent.merkle_hash, MERKLE_HASH_SIZE);
        p += sprintf(p, "\"");
    }
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_work_header_hex_properties(char *buf, const struct work_header *header)
{
    char *p = buf;

    p += sprintf(p, "\"featureFlags\":\"0x%.16llx\",", header->flags);
    p += sprintf(p, "\"creationTime\":%llu,", header->time);

    p += sprintf(p, "\"parent\":\"");
    p += hex(p, header->parent.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"adjacents\":");
    p += json_adjacents_hex(p, &header->adjacents);
    p += sprintf(p, ",");

    p += sprintf(p, "\"target\":\"");
    p += hex(p, header->target.pow_nat, POWNAT_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"payloadHash\":\"");
    p += hex(p, header->payload.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"chainId\":%d,", header->chain);

    p += sprintf(p, "\"weight\":\"");
    p += hex(p, header->weight.pow_nat, POWNAT_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"height\":%d,", header->height);

    p += sprintf(p, "\"chainwebVersion\":");
    p += json_version(p, header->version);
    p += sprintf(p, ",");

    p += sprintf(p, "\"epochStart\":%llu,", header->epoch);
    p += sprintf(p, "\"nonce\": \"0x%.16llx\"", header->nonce);

    *p = 0;
    return p - buf;
}

int json_work_header_hex(char *buf, const struct work_header *header)
{
    char *p = buf;
    p += sprintf(p, "{");
    p += json_work_header_hex_properties(p, header);
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_header_hex(char *buf, const struct header *header)
{
    char *p = buf;
    p += sprintf(p, "{");
    p += json_work_header_hex_properties(p, (struct work_header *) header);
    p += sprintf(p, ",");
    p += sprintf(p, "\"hash\":\"");
    p += hex(p, header->hash.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\"");
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_adjacents_b64(char *buf, const Adjacents* adjs)
{
    char *p = buf;

    p += sprintf(p, "{");

    for (size_t i = 0; i < CHAINWEB_DEGREE; ++i) {
        if (i > 0) {
            p += sprintf(p, ",");
        }
        p += sprintf(p, "\"%d\":\"", (adjs->adjacent_parents)[i].chain);
        p += b64_encode(p, (adjs->adjacent_parents)[i].parent.merkle_hash, MERKLE_HASH_SIZE);
        p += sprintf(p, "\"");
    }
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_work_header_b64_properties(char *buf, const struct work_header *header)
{
    char *p = buf;

    p += sprintf(p, "\"featureFlags\":\"0x%.16llx\",", header->flags);
    p += sprintf(p, "\"creationTime\":%llu,", header->time);

    p += sprintf(p, "\"parent\":\"");
    p += b64_encode(p, header->parent.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"adjacents\":");
    p += json_adjacents_b64(p, &header->adjacents);
    p += sprintf(p, ",");

    p += sprintf(p, "\"target\":\"");
    p += b64_encode(p, header->target.pow_nat, POWNAT_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"payloadHash\":\"");
    p += b64_encode(p, header->payload.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"chainId\":%d,", header->chain);

    p += sprintf(p, "\"weight\":\"");
    p += b64_encode(p, header->weight.pow_nat, POWNAT_SIZE);
    p += sprintf(p, "\",");

    p += sprintf(p, "\"height\":%d,", header->height);

    p += sprintf(p, "\"chainwebVersion\":");
    p += json_version(p, header->version);
    p += sprintf(p, ",");

    p += sprintf(p, "\"epochStart\":%llu,", header->epoch);
    p += sprintf(p, "\"nonce\": \"0x%.16llx\"", header->nonce);

    *p = 0;
    return p - buf;
}

int json_header_b64(char *buf, const struct header *header)
{
    char *p = buf;
    p += sprintf(p, "{");
    p += json_work_header_b64_properties(p, (struct work_header *) header);
    p += sprintf(p, ",");
    p += sprintf(p, "\"hash\":\"");
    p += b64_encode(p, header->hash.merkle_hash, MERKLE_HASH_SIZE);
    p += sprintf(p, "\"");
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_work_header_b64(char *buf, const struct work_header *header)
{
    char *p = buf;
    p += sprintf(p, "{");
    p += json_work_header_b64_properties(p, header);
    p += sprintf(p, "}");
    *p = 0;
    return p - buf;
}

int json_header_hex_ (const struct header* header)
{
    size_t buf32Size = MERKLE_HASH_SIZE * 2;
    size_t adjBufSize = CHAINWEB_DEGREE * (6 /* JSON markup */ + 2 /*ChainID */ + MERKLE_HASH_SIZE * 2 /* hex hash */);
    size_t other = 2 + 13 * 5 + 7 * 32;
    size_t all = buf32Size * 5 + adjBufSize + other;
    char *buf = (char *) malloc(all);
    int x = json_header_hex(buf, header);
    fputs(buf, stdout);

    free(buf);
    return x;
}

int json_work_header_hex_ (const struct work_header* header)
{
    size_t buf32Size = MERKLE_HASH_SIZE * 2;
    size_t adjBufSize = CHAINWEB_DEGREE * (6 /* JSON markup */ + 2 /*ChainID */ + MERKLE_HASH_SIZE * 2 /* hex hash */);
    size_t other = 2 + 13 * 5 + 6 * 32;
    size_t all = buf32Size * 5 + adjBufSize + other;
    char *buf = (char *) malloc(all);
    int x = json_work_header_hex(buf, header);
    fputs(buf, stdout);

    free(buf);
    return x;
}

int json_header_b64_ (const struct header* header)
{
    size_t buf32Size = MERKLE_HASH_SIZE * 2;
    size_t adjBufSize = CHAINWEB_DEGREE * (6 /* JSON markup */ + 2 /*ChainID */ + MERKLE_HASH_SIZE * 2 /* hex hash */);
    size_t other = 2 + 13 * 5 + 7 * 32;
    size_t all = buf32Size * 5 + adjBufSize + other;
    char *buf = (char *) malloc(all);
    int x = json_header_b64(buf, header);
    fputs(buf, stdout);

    free(buf);
    return x;
}

int json_work_header_b64_ (const struct work_header* header)
{
    size_t buf32Size = MERKLE_HASH_SIZE * 2;
    size_t adjBufSize = CHAINWEB_DEGREE * (6 /* JSON markup */ + 2 /*ChainID */ + MERKLE_HASH_SIZE * 2 /* hex hash */);
    size_t other = 2 + 13 * 5 + 6 * 32;
    size_t all = buf32Size * 5 + adjBufSize + other;
    char *buf = (char *) malloc(all);
    int x = json_work_header_b64(buf, header);
    fputs(buf, stdout);

    free(buf);
    return x;
}

/* ************************************************************************** */
/* Tests */

int test_main (void)
{
    struct header header;
    HeaderBytes *bin = (HeaderBytes *) malloc(sizeof(HeaderBytes));
    decode_base64Url(bin->header_bytes, test3, strlen(test3));
    read_header(bin, &header);

    json_header_hex_(&header);
    printf("\n");
    json_header_b64_(&header);
    printf("\n");

    free(bin);
    return 0;
}

/* ************************************************************************** */
/* Main */

/* TODO:
 *
 * - command line arguments for output format
 * - support more work header encodings
 */

void info(FILE* f)
{
    fprintf(f, "decode-header - a tool for printing Kadena chainweb headers in JSON format\n");
}

void usage(FILE* f)
{
    fprintf(f, "USAGE:\n");
    fprintf(f, "\n");
    fprintf(f, "Options\n");
    fprintf(f, "  --help, -?\n");
    fprintf(f, "  --version, -v\n");
    fprintf(f, "\n");
    fprintf(f, "Stdin: newline separated lines of size of either\n");
    fprintf(f, "  - %lu (binary)\n", sizeof(HeaderBytes));
    fprintf(f, "  - %lu (hex)\n", sizeof(HeaderBytes) * 2);
    fprintf(f, "  - %lu (hex with 0x prefix)\n", sizeof(HeaderBytes) * 2 + 2);
    fprintf(f, "  - %lu (quoted hex)\n", sizeof(HeaderBytes) * 2 + 2);
    fprintf(f, "  - %lu (quoted hex with 0x prefix)\n", sizeof(HeaderBytes) * 2 + 4);
    fprintf(f, "  - 424 (base64)\n");
    fprintf(f, "  - 426 (quoted base64)\n");
}

int main(int argc, char **argv)
{
    size_t len = (sizeof(HeaderBytes) * 2 + 2) * sizeof(char);
    char *buffer = (char *) malloc(len);
    char *line;
    ssize_t n;
    int i;

    struct header header;
    struct work_header work_header;
    HeaderBytes b;
    HeaderBytes* bin = &b;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            info(stdout);
            fprintf(stdout, "\n");
            usage(stdout);
            exit(0);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            info(stdout);
            exit(0);
        } else {
            fprintf(stderr, "unrecognized command line option: %s\n", argv[i]);
            exit(1);
        }
    }

    while ((n = getline(&buffer, &len, stdin)) >= 0) {

        // binary input mode
        if (n <= (ssize_t) sizeof(HeaderBytes)) {
            if (n < (ssize_t) sizeof(HeaderBytes)) {
                n += fread(&buffer[n], 1, sizeof(HeaderBytes) - n, stdin);
                if (n < (ssize_t) sizeof(HeaderBytes)) {
                    fprintf(stderr, "binary header has wrong length: %lu\n", n);
                    fprintf(stderr, "line: %s\n\n", buffer);
                    usage(stderr);
                    exit(1);
                }
            }
            read_header((HeaderBytes *)buffer, &header);

        // text input mode
        } else {

            line = buffer;

            // strip pending newline (if any)
            if (line[n-1] == '\n') {
            n = n - 1;
            }

            // strip quotes (if any)
            if (line[0] == '"' && line[n-1] == '"') {
                line = line + 1;
                n = n - 2;
            }

            // base64 encoded input
            if (n == 424) {
                decode_base64Url(bin->header_bytes, line, n);
                read_header(bin, &header);

            // hex input with prefix
            } else if (n == 2 + sizeof(HeaderBytes) * 2) {
                decode_hex(bin->header_bytes, line + 2, n-2);
                read_header((HeaderBytes *)bin, &header);

            // hex input
            } else if (n == sizeof(HeaderBytes) * 2) {
                decode_hex(bin->header_bytes, line, n);
                read_header((HeaderBytes *)bin, &header);

            // hex work header (sent to miner)
            } else if (n == sizeof(WorkHeaderBytes) * 2) {
                decode_hex(bin->header_bytes, line, n);
                read_work_header((WorkHeaderBytes *)bin, &work_header);
                json_work_header_b64_(&work_header);
                fputc('\n', stdout);
                continue;

            // error
            } else {
                fprintf(stderr, "header has wrong length: %lu\n", n);
                fprintf(stderr, "line: %s\n\n", line);
                usage(stderr);
                exit(1);
            }
        }

        json_header_b64_(&header);
        fputc('\n', stdout);
    }

    free(buffer);
    return 0;
}

