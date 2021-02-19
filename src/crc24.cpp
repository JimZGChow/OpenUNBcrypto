#include "crc24.h"

#define CRC24_INIT      0xFFFFFFUL
#define CRC24_POLY      0x5D6DCBUL
#define CRC24_XOR_OUT   0xFFFFFFUL

uint32_t crc24(unsigned char* octets, size_t len) {
    uint32_t crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return (crc & 0xFFFFFFL) ^ CRC24_XOR_OUT ;
}
