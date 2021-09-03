#include "OpenUNBEncrypterLL.h"

#if defined(AES128) | defined(AES256)
#include "aes.h"
#else
#include <libakrypt.h>
#endif

#if defined(AES128) | defined(AES256)
void aes128Enc(uint8_t* key, uint8_t* data, uint8_t* ret);
//void aesCTR(uint8_t* key, uint8_t* iv, uint8_t* data, uint8_t* ret);
void aesCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret);
void aesECB(uint8_t* key, uint8_t*  data, uint8_t* ret);
void aesCMAC(uint8_t* key, uint8_t* data, size_t size, uint8_t* ret);
#endif

#if defined(KUZNECHIK) | defined(MAGMA)
void kzchMgmCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret);
void kzchMgmECB(uint8_t* key, uint8_t* data, uint8_t* ret);
void kzchMgmCMAC(uint8_t* key, uint8_t* data, size_t size, uint8_t* ret);
#endif

void encECB(uint8_t* key, uint8_t* data, uint8_t* ret);
void encCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret);
uint32_t encCMAC(uint8_t* key, uint8_t* data, size_t size);

void mem_swap(void* mem, size_t n) {
    uint8_t tmp;
    uint8_t* mem_ptr = (uint8_t*)mem;
    for (int i=0; i<n/2; i++) {
        tmp = mem_ptr[i];
        mem_ptr[i] = mem_ptr[n - 1 - i];
        mem_ptr[n - 1 - i] = tmp;
    }
}

void memcpy_endian(void* dest, const void* src, size_t n) {
#ifndef AK_BIG_ENDIAN
    for (int i=0; i < n; i++) {
        ((char*)dest)[n - 1 - i] = ((char*)src)[i];
    }
#else
    memcpy(dest, src, n);
#endif
}

int init_encrypter() {
#if defined(KUZNECHIK) | defined(MAGMA)
    if( !ak_libakrypt_create( ak_function_log_stderr ))
        return ak_libakrypt_destroy();
    ak_libakrypt_set_openssl_compability( ak_false );
#endif

    return 0;
}

uint32_t getDevAddr(uint8_t* Ka, uint32_t Ne) {
    uint32_t ret = 0;

    uint8_t tmp[KEYSIZE_BYTE] = {0};
    uint8_t tmp_ret[KEYSIZE_BYTE] = {0};

    // 0x01 || Ne || 00..00
    memset(tmp, 0, KEYSIZE_BYTE);
    tmp[0] = 0x01;
    memcpy_endian(tmp + 1, &Ne, sizeof(Ne));

    encECB(Ka, tmp, tmp_ret);

    memcpy_endian(&ret, tmp_ret, 4);

    ret = ret & 0xFFFFFF;

    return ret;
}

void getKa(uint8_t* K0, uint16_t Na, uint8_t* Ka) {
    memset(Ka, 0, KEYSIZE_BYTE);

    uint8_t iv[IVSIZE] = {0};

    //Na || 00..00
    memcpy_endian(iv, &Na, sizeof(Na));

    uint8_t t[KEYSIZE_BYTE] = {0};

    encCTR(K0, iv, t, KEYSIZE_BYTE, Ka);
}

void getKm(uint8_t* Ka, uint32_t Ne, uint8_t* ret) {
    // 0x02 || Ne || 00..00
    uint8_t iv[IVSIZE] = {0};
    iv[0] = 0x02;
    memcpy_endian(iv + 1, &Ne, sizeof(Ne));

    uint8_t t[KEYSIZE_BYTE] = {0};
    encCTR(Ka, iv, t, KEYSIZE_BYTE, ret);
}



void getKe(uint8_t* Ka, uint32_t Ne, uint8_t* Ke) {

    // 0x03 || Ne || 00..00
    uint8_t iv[IVSIZE] = {0};
    iv[0] = 0x03;
    memcpy_endian(iv + 1, &Ne, sizeof(Ne));

    uint8_t t[KEYSIZE_BYTE] = {0};
    encCTR(Ka, iv, t, KEYSIZE_BYTE, Ke);
}


int cryptoMacPayload(uint8_t* macPayloadIn, uint8_t* macPayloadOut, uint8_t size, uint8_t* Ke, uint16_t Nn) {
    if (size != 2 && size != 6)
        return -1;

    uint8_t iv[IVSIZE] = {0};
    uint8_t tmpRet[KEYSIZE_BYTE] = {0};

    //Nn || 00..00
    memcpy_endian(iv, &Nn, sizeof(Nn));

    uint8_t t[KEYSIZE_BYTE] = {0};
    memcpy(t, macPayloadIn, size);

    encCTR(Ke, iv, t, KEYSIZE_BYTE, tmpRet);

    memcpy(macPayloadOut, tmpRet, size);

    return 0;
}

int getMIC(uint8_t* Km, uint32_t DevAddr, uint8_t* dataIn, uint8_t* dataOut, uint8_t size, uint16_t Nn) {
    if (size != 2 && size != 6)
        return -1;


    uint8_t P[16] = { 0 };

    // 00..00
    memset(P, 0, sizeof(P));
    // DevAddr || 00..00
    memcpy_endian(P, &DevAddr, 4);
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P + 3, dataIn, size);
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy_endian(P + 3 + size, &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P[sizeof (P) - 1] = 0x10;

#if defined(MAGMA)
    // DevAddr || cryptoMacPayload || Nn || 0x10 for short MAGMA
    if (size == 2) {
        P[7] = 0x10;
    }
#endif

#if defined(AES128) || defined(AES256)
    uint8_t R[KEYSIZE_BYTE] = {0};
    uint8_t K1[KEYSIZE_BYTE] = {0};
    uint8_t t[KEYSIZE_BYTE] = {0};

    aesECB(Km, t, R);

    uint8_t msb = (R[0] >> 7) & 1;

    // R << 1
    for (int i = sizeof(R) - 1; i >= 0; i--) {
        R[i] = R[i] << 1;
        if (i != 0)
            R[i] |= (R[i - 1] >> 7) & 1;
    }

    // if ( MSB1(R) = 1)
    if (msb) {
        uint8_t B[KEYSIZE_BYTE] = {0};
        B[0] = 0b10000111;

        for (unsigned int i = 0; i < sizeof(K1); i++) {
            K1[i] = R[i] ^ B[i];
        }
    }
    // if ( MSB1(R) = 0)
    else {
        for (unsigned int i = 0; i < sizeof(K1); i++) {
            K1[i] = R[i];
        }
    }

    for (unsigned int i = 0; i < sizeof(P); i++) {
        K1[i] ^= P[i];
    }

    uint8_t tmp[KEYSIZE_BYTE];

    aesECB(Km, K1, tmp);

    for (int i = 0; i < 3; i++)
        dataOut[i] = tmp[i];

#elif defined(KUZNECHIK)
    kzchMgmCMAC(Km, P.data, 128 / 8, dataOut);
#elif defined(MAGMA)
    if (size == 2)
        kzchMgmCMAC(Km, P, 8, dataOut);
    else
        kzchMgmCMAC(Km, P, 8 * 2, dataOut);
#endif

    return 0;
}


#if defined(AES128) | defined(AES256)
void aes128Enc(uint8_t* key, uint8_t* data, uint8_t* ret) {

    struct AES_ctx _key;
    memcpy_endian(ret, data, KEYSIZE_BYTE);
    uint8_t iv[KEYSIZE_BYTE] = {0};

    AES_init_ctx_iv(&_key, key, iv);
    AES_CTR_xcrypt_buffer(&_key, ret, KEYSIZE_BYTE);
}

void aesCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret) {
    struct AES_ctx _key;
    memcpy(ret, data, size);
    AES_init_ctx_iv(&_key, key, iv);
    AES_CTR_xcrypt_buffer(&_key, ret, size);
}

void aesECB(uint8_t* key, uint8_t* data, uint8_t* ret) {
    struct AES_ctx _key;
    memcpy(ret, data, KEYSIZE_BYTE);

    AES_init_ctx(&_key, key);

    AES_ECB_encrypt(&_key, ret);
}

//uint24a_t aesCMAC(uint128_256_t key, uint8_t* data, size_t size) {
//    // TODO
//    //return {0};
//}
#endif


#if defined(KUZNECHIK) | defined(MAGMA)

void kzchMgmCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret) {

    struct bckey bkey;
    int error;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    }
    if(( error = ak_bckey_set_key( &bkey, key, KEYSIZE_BYTE)) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
      }

    ak_bckey_ctr(&bkey, data, ret, size, iv, IVSIZE);
}

void kzchMgmECB(uint8_t* key, uint8_t* data, uint8_t* ret) {
    struct bckey bkey;
    int error;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    }
    if(( error = ak_bckey_set_key( &bkey, key, KEYSIZE_BYTE)) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
      }

    ak_bckey_encrypt_ecb(&bkey, data, ret, KEYSIZE_BYTE);
}

void kzchMgmCMAC(uint8_t* key, uint8_t* data, size_t size, uint8_t* ret) {
    struct bckey bkey;
    int error;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    }
    if(( error = ak_bckey_set_key( &bkey, key, KEYSIZE_BYTE)) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
      }

    //ak_bckey_cmac(&bkey, data, size, ret, sizeof(ret));
    ak_bckey_cmac(&bkey, data, size, ret, 3);
    //return ret;
}
#endif

void encECB(uint8_t* key, uint8_t* data, uint8_t* ret) {

#if defined(AES128)
    aesECB(key, data, ret);//aes128Enc(Ka, tmp);
#endif

#if defined(KUZNECHIK) | defined(MAGMA)
    kzchMgmECB(key, data, ret);
#endif
}

void encCTR(uint8_t* key, uint8_t* iv, uint8_t* data, size_t size, uint8_t* ret) {
#if defined(AES128)
    aesCTR(key, iv, data, size, ret);
#endif
#if defined(KUZNECHIK) | defined(MAGMA)
    kzchMgmCTR(key, iv, data, size, ret);
#endif
}
