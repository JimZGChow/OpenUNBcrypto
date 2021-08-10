#ifndef OPENUNBTYPES_H
#define OPENUNBTYPES_H

#include <stdint.h>
#include <time.h>

#define AES128

#ifdef AES128
#define KEYSIZE         128
#define KEYSIZE_BYTE    16
#define IVSIZE          16
#else
#define KEYSIZE 256
#ifdef MAGMA
#define IVSIZE          4
#else
#define IVSIZE          8
#endif

#endif

struct encrypt_data_t {
    uint8_t* DevID;
    uint8_t DevID_len;
    uint8_t K0[KEYSIZE_BYTE];
    uint16_t Na;
    uint32_t Ne;

    uint8_t Ka[KEYSIZE_BYTE];
    uint32_t dev_addr;
    uint8_t Km[KEYSIZE_BYTE];
    uint8_t Ke[KEYSIZE_BYTE];

    uint16_t Nn;
    time_t init_time;

    uint16_t Nn_last;
    uint32_t Ne_last;
} __attribute__((packed));

#endif // OPENUNBTYPES_H
