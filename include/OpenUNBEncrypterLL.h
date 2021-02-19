#ifndef OPENUNBDECRYPTERLL_H
#define OPENUNBDECRYPTERLL_H

#include <stdint.h>
#include <memory>
#include <string.h>

#include "OpenUNBTypes.h"

//#define AES128
//#define AES256
//#define KUZNECHIK
//#define MAGMA

#if defined(AES128) | defined(AES256)
#include "aes.h"
#else
#include <libakrypt.h>
#endif 


int init();

uint128_256_t getKa(uint128_256_t K0, uint16_t Na);

uint24a_t getDevAddr(uint128_256_t Ka, uint24a_t Ne);

uint128_256_t getKm(uint128_256_t Ka, uint24a_t Ne);

uint128_256_t getKe(uint128_256_t Ka, uint24a_t Ne);

uint16_t cryptoMacPayload16(uint16_t macPayload, uint128_256_t Ke, uint16_t Nn);
uint48a_t cryptoMacPayload48(uint48a_t macPayload, uint128_256_t Ke, uint16_t Nn);

uint24a_t getMIC16(uint128_256_t Km, uint24a_t DevAddr, uint16_t cryptoMacPayload, uint16_t Nn);
uint24a_t getMIC48(uint128_256_t Km, uint24a_t DevAddr, uint48a_t cryptoMacPayload, uint16_t Nn);

#endif
