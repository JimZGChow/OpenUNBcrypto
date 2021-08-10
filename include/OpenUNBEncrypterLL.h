#ifndef OPENUNBDECRYPTERLL_H
#define OPENUNBDECRYPTERLL_H

#include <stdint.h>
#include <string.h>

#include "OpenUNBTypes.h"

//#define AES128
//#define AES256
//#define KUZNECHIK
//#define MAGMA


int init_encrypter();

void getKa(uint8_t* K0, uint16_t Na, uint8_t* Ka);

uint32_t getDevAddr(uint8_t* Ka, uint32_t Ne);

void getKm(uint8_t* Ka, uint32_t Ne, uint8_t* Km);

void getKe(uint8_t* Ka, uint32_t Ne, uint8_t* Ke);

int cryptoMacPayload(uint8_t* macPayloadIn, uint8_t* macPayloadOut, uint8_t size, uint8_t* Ke, uint16_t Nn);

int getMIC(uint8_t* Km, uint32_t DevAddr, uint8_t* dataIn, uint8_t* dataOut, uint8_t size, uint16_t Nn);

void memcpy_endian(void* dest, const void* src, size_t n);
#endif
