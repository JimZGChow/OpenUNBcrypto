#ifndef OPENUNBTYPES_H
#define OPENUNBTYPES_H

#include <stdint.h>

#ifdef AES128
#define KEYSIZE 128
#else
#define KEYSIZE 256
#endif

#if defined(MAGMA)
struct iv_t {
    uint8_t data[4];
};
#elif defined(KUZNECHIK)
struct iv_t {
    uint8_t data[8];
};
#else

struct iv_t {
    uint8_t data[16];
} __attribute__((packed));
#endif

struct uint256a_t {
    uint8_t data[32];
}  __attribute__((packed));

struct uint128a_t {
    uint8_t data[16];
} __attribute__((packed));

union uint64a_t {
    uint8_t data[8];
    uint64_t ud;
} __attribute__((packed));

union uint48a_t {
    uint8_t data[6];
    uint64_t ud : 48;
} __attribute__((packed));

union uint24a_t {
    uint8_t data[3];
    uint32_t ud : 24;
} __attribute__((packed));

#if KEYSIZE == 128
typedef uint128a_t uint128_256_t;
#else
typedef uint256a_t uint128_256_t;
#endif

struct encryptInitData {
    uint8_t* DevID;
    uint8_t DevID_len;
    uint128_256_t K0;
    uint16_t Na;
    uint24a_t Ne;
} __attribute__((packed));

#endif // OPENUNBTYPES_H
