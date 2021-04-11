#include "OpenUNBEncrypterLL.h"

#if defined(AES128) | defined(AES256)
#include "aes.h"
#else
#include <libakrypt.h>
#endif

encryptInitData* _info = nullptr;

uint128_256_t aes128Enc(uint128_256_t key, uint128_256_t data);
uint128_256_t aesCTR(uint128_256_t key, iv_t iv, uint128_256_t data);
uint128_256_t aesCTR(uint128_256_t key, iv_t iv, uint8_t* data, size_t size);
uint128_256_t aesECB(uint128_256_t key, uint128_256_t data);
uint24a_t aesCMAC(uint128_256_t key, uint8_t* data, size_t size);

uint128_256_t kzchMgmCTR(uint128_256_t key, iv_t iv, uint128_256_t data);
uint128_256_t kzchMgmCTR(uint128_256_t key, iv_t iv, uint8_t* data, size_t size);
uint128_256_t kzchMgmECB(uint128_256_t key, uint128_256_t data);
uint24a_t kzchMgmCMAC(uint128_256_t key, uint8_t* data, size_t size);

uint128_256_t encECB(uint128_256_t key, uint128_256_t data);
uint128_256_t encCTR(uint128_256_t key, iv_t iv, uint128_256_t data);
uint24a_t encCMAC(uint128_256_t key, uint8_t* data, size_t size);


int init() {
#if defined(KUZNECHIK) | defined(MAGMA)
    if( !ak_libakrypt_create( ak_function_log_stderr ))
        return ak_libakrypt_destroy();
    ak_libakrypt_set_openssl_compability( ak_false );
#endif

    return 0;
}

uint128_256_t getKa(uint128_256_t K0, uint16_t Na) {
    uint128_256_t ret = { 0 };
    iv_t iv = {0};

    //Na || 00..00
    memcpy((char*)&iv + sizeof(iv.data) - sizeof(Na), &Na, sizeof(Na));
    uint128_256_t t = {0};

    ret = encCTR(K0, iv, t);

    return ret;
}


uint24a_t getDevAddr(uint128_256_t Ka, uint24a_t Ne) {
    uint24a_t ret = { 0 };
    uint128_256_t tmp = { 0 };
    uint128_256_t tmpRet = { 0 };

    // 0x01 || Ne || 00..00
    memset(tmp.data, 0, sizeof(tmp.data));
    tmp.data[sizeof(tmp.data) - 1] = 0x01;
    memcpy(tmp.data + sizeof(tmp.data) - sizeof(Ne) - 1, &Ne, sizeof(Ne));

    tmpRet = encECB(Ka, tmp);

    memcpy(ret.data, tmpRet.data + sizeof(tmpRet.data) - sizeof(ret.data), sizeof(ret.data));

    return ret;
}

uint128_256_t getKm(uint128_256_t Ka, uint24a_t Ne) {
    uint128_256_t ret = { 0 };

    // 0x02 || Ne || 00..00
    iv_t iv = {0};
    iv.data[sizeof(iv) - 1] = 0x02;
    memcpy(iv.data + sizeof(iv.data) - sizeof(Ne) - 1, &Ne, sizeof(Ne));

    uint128_256_t t = {0};
    ret = encCTR(Ka, iv, t);

    return ret;
}

uint128_256_t getKe(uint128_256_t Ka, uint24a_t Ne) {
    uint128_256_t ret = { 0 };

    // 0x02 || Ne || 00..00
    iv_t iv = {0};
    iv.data[sizeof(iv) - 1] = 0x03;
    memcpy(iv.data + sizeof(iv.data) - sizeof(Ne) - 1, &Ne, sizeof(Ne));

    uint128_256_t t = {0};
    ret = encCTR(Ka, iv, t);

    return ret;
}

uint16_t cryptoMacPayload16(uint16_t macPayload, uint128_256_t Ke, uint16_t Nn) {
    uint16_t ret;
    iv_t iv = {0};
    uint128_256_t tmpRet = { 0 };

    //Nn || 00..00
    memcpy((char*)&iv + sizeof(iv.data) - sizeof(Nn), &Nn, sizeof(Nn));

    uint128_256_t t = {0};
    memcpy(t.data, &macPayload, sizeof(macPayload));

    tmpRet = encCTR(Ke, iv, t);

    // MSB
    ret = (tmpRet.data[1] << 8) | (tmpRet.data[0]);

    return ret;
}

uint48a_t cryptoMacPayload48(uint48a_t macPayload, uint128_256_t Ke, uint16_t Nn) {
    uint48a_t ret;
    iv_t iv = {0};
    uint128_256_t tmpRet = { 0 };

    // Ne || 00..00
    memcpy((char*)&iv + sizeof(iv.data) - sizeof(Nn), &Nn, sizeof(Nn));

    uint128_256_t t = {0};
    memcpy(t.data, macPayload.data, sizeof(macPayload.data));
    tmpRet = encCTR(Ke, iv, t);

    memcpy(ret.data, tmpRet.data, sizeof(ret.data));

    return ret;
}

uint24a_t getMIC16(uint128_256_t Km, uint24a_t DevAddr, uint16_t cryptoMacPayload, uint16_t Nn) {
    uint24a_t ret = { 0 };

    //printf("getMIC16(%x, %x, %x, %x)\n", Km.data[0], DevAddr.ud, cryptoMacPayload, Nn);
#if defined(AES128) || defined(AES256) || defined(KUZNECHIK)
    uint128a_t P = { 0 };
#else
    uint64a_t P;
#endif
    // 00..00
    memset(P.data, 0, sizeof(P.data));
    // DevAddr || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data), DevAddr.data, sizeof(DevAddr.data));
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data) - sizeof(cryptoMacPayload), &cryptoMacPayload, sizeof(cryptoMacPayload));
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data) - sizeof(cryptoMacPayload) - sizeof(Nn), &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P.data[0] = 0x10;
#if defined(AES128) || defined(AES256)

    uint128_256_t R = { 0 };
    uint128_256_t K1 = { 0 };
    uint128_256_t t = {0};

    R = aesECB(Km, t);

    bool msb = (R.data[sizeof(R.data) - 1] >> 7) & 1;

    // R << 1
    for (int i = sizeof(R.data) - 1; i >= 0; i--) {
        R.data[i] = R.data[i] << 1;
        if (i != 0)
            R.data[i] |= (R.data[i - 1] >> 7) & 1;
    }

    // if ( MSB1(R) = 1)
    if (msb) {
        uint128_256_t B = {0};
        B.data[0] = 0b10000111;

        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i] ^ B.data[i];
        }
    }
    // if ( MSB1(R) = 0)
    else {
        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i];
        }
    }

    for (unsigned int i = 0; i < sizeof(P.data); i++) {
        K1.data[i] ^= P.data[i];
    }

    t = {0};
    uint128_256_t tmp;

    tmp = aesECB(Km, K1);

    for (int i = 0; i < sizeof(ret.data); i++)
        ret.data[i] = tmp.data[sizeof(tmp.data) - sizeof(ret.data) + i];

#elif defined(KUZNECHIK)
    ret = kzchMgmCMAC(Km, P.data, 128 / 8);
#elif defined(MAGMA)
    ret = kzchMgmCMAC(Km, P.data, 64 / 8);
#endif

    return ret;
}

uint24a_t getMIC48(uint128_256_t Km, uint24a_t DevAddr, uint48a_t cryptoMacPayload, uint16_t Nn) {
    uint24a_t ret = { 0 };

#if defined(AES128) || defined(AES256) || defined(KUZNECHIK)
    uint128a_t P;
#else
    uint64a_t P;
#endif
    // 00..00
    memset(P.data, 0, sizeof(P.data));
    // DevAddr || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data), DevAddr.data, sizeof(DevAddr.data));
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data) - sizeof(cryptoMacPayload.data), cryptoMacPayload.data, sizeof(cryptoMacPayload).data);
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr.data) - sizeof(cryptoMacPayload.data) - sizeof(Nn), &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P.data[0] = 0x30;

#if defined(AES128) || defined(AES256)
    uint128_256_t R;
    uint128_256_t K1;
    uint128_256_t t = {0};

    R = aesECB(Km, t);

    bool msb = (R.data[sizeof(R.data) - 1] >> 7) & 1;

    // R << 1
    for (int i = sizeof(R.data) - 1; i >= 0; i--) {
        R.data[i] = R.data[i] << 1;
        if (i != 0)
            R.data[i] |= (R.data[i - 1] >> 7) & 1;
    }

    // if ( MSB1(R) = 1)
    if (msb) {
        uint128_256_t B = {0};
        B.data[0] = 0b10000111;

        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i] ^ B.data[i];
        }
    }
    // if ( MSB1(R) = 0)
    else {
        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i];
        }
    }

    for (unsigned int i = 0; i < sizeof(P.data); i++) {
        K1.data[i] ^= P.data[i];
    }

    t = {0};
    uint128_256_t tmp;

    tmp = aesECB(Km, K1);

    for (int i = 0; i < sizeof(ret.data); i++)
        ret.data[i] = tmp.data[sizeof(tmp.data) - sizeof(ret.data) + i];

#elif defined(KUZNECHIK)
    ret = kzchMgmCMAC(Km, P.data, 128 / 8);
#elif defined(MAGMA)
    ret = kzchMgmCMAC(Km, P.data, 64 / 8);
#endif

    return ret;
}

/*
uint24_t getMIC16(uint128_256_t Km, uint24_t DevAddr, uint16_t cryptoMacPayload, uint16_t Nn) {
    uint128_256_t R;
    uint128_256_t K1;
    uint24_t ret = { 0 };
    bool msb;

    iv_t iv = {0};

    uint128_256_t t = {0};
#if defined(AES128)
    R = aes128Enc(Km, t);


    msb = (R.data[sizeof(R.data) - 1] >> 7) & 1;

    // R << 1
    for (int i = sizeof(R.data) - 1; i >= 0; i--) {
        R.data[i] = R.data[i] << 1;
        if (i != 0)
            R.data[i] |= (R.data[i - 1] >> 7) & 1;
    }

    // if ( MSB1(R) = 1)
    if (msb) {
        uint128_256_t B;
        memset(B.data, 0, sizeof(B.data));
        B.data[0] = 0b10000111;

        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i] ^ B.data[i];
        }
    }
    // if ( MSB1(R) = 0)
    else {
        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i];
        }
    }

    uint128_256_t P;
    // 00..00
    memset(P.data, 0, sizeof(P.data));
    // DevAddr || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr), &DevAddr, sizeof(DevAddr));
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr) - sizeof(cryptoMacPayload), &cryptoMacPayload, sizeof(cryptoMacPayload));
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr) - sizeof(cryptoMacPayload) - sizeof(Nn), &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P.data[0] = 0x10;

    for (unsigned int i = 0; i < sizeof(P.data); i++) {
        K1.data[i] ^= P.data[i];
    }

    t = {0};
    uint128_256_t tmp;

    tmp = aes128Enc(Km, K1);



    for (int i = 0; i < sizeof(ret.data); i++)
        ret.data[i] = tmp.data[sizeof(tmp.data) - sizeof(ret.data) + i];

#endif

    //uint128_t P;
#ifdef KUZNECHIK
    size_t PSize = 128 / 8;
#else
    size_t PSize = 64 / 8;
#endif
    // 00..00
    memset(P.data, 0, PSize);
    // DevAddr || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr), &DevAddr, sizeof(DevAddr));
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr) - sizeof(cryptoMacPayload), &cryptoMacPayload, sizeof(cryptoMacPayload));
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr) - sizeof(cryptoMacPayload) - sizeof(Nn), &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P.data[0] = 0x10;

#if defined(KUZNECHIK) | defined(MAGMA)
    ret = kzchMgmCMAC(Km, P.data, PSize);
#endif
    return ret;
}

uint24_t getMIC48(uint128_256_t Km, uint24_t DevAddr, uint48_t cryptoMacPayload, uint16_t Nn) {
    uint128_256_t R;
    uint128_256_t K1;
    uint24_t ret = { 0 };
    bool msb;

    uint128_256_t tmp = {0};
#if defined(AES128)
    R = aes128Enc(Km, tmp);


    msb = (R.data[sizeof(R.data) - 1] >> 7) & 1;

    for (int i = sizeof(R.data) - 1; i >= 0; i--) {
        R.data[i] = R.data[i] << 1;
        if (i != 0)
            R.data[i] |= (R.data[i - 1] >> 7) & 1;
    }

    if (msb) {
        uint128_256_t B;
        memset(B.data, 0, sizeof(B.data));
        B.data[0] = 0b10000111;

        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i] ^ B.data[i];
        }
    }
    else {
        for (unsigned int i = 0; i < sizeof(K1.data); i++) {
            K1.data[i] = R.data[i];
        }
    }

    uint128_256_t P;
    memset(P.data, 0, sizeof(P.data));
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr), &DevAddr, sizeof(DevAddr));
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr) - sizeof(cryptoMacPayload), &cryptoMacPayload, sizeof(cryptoMacPayload));
    memcpy(P.data + sizeof(P.data) - sizeof(DevAddr) - sizeof(cryptoMacPayload) - sizeof(Nn), &Nn, sizeof(Nn));
    P.data[0] = 0x30;

    for (unsigned int i = 0; i < sizeof(P.data); i++) {
        K1.data[i] ^= P.data[i];
    }

    tmp = aes128Enc(Km, K1);


    for (unsigned int i = 0; i < sizeof(ret.data); i++)
        ret.data[i] = tmp.data[sizeof(tmp.data) - sizeof(ret.data) + i];

#endif

    //uint128_t P;
#ifdef KUZNECHIK
    size_t PSize = 128 / 8;
#else
    size_t PSize = 64 / 8;
#endif
    // 00..00
    memset(P.data, 0, PSize);
    // DevAddr || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr), &DevAddr, sizeof(DevAddr));
    // DevAddr || cryptoMacPayload || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr) - sizeof(cryptoMacPayload), &cryptoMacPayload, sizeof(cryptoMacPayload));
    // DevAddr || cryptoMacPayload || Nn || 00..00
    memcpy(P.data + PSize - sizeof(DevAddr) - sizeof(cryptoMacPayload) - sizeof(Nn), &Nn, sizeof(Nn));
    // DevAddr || cryptoMacPayload || Nn || 00..00 || 0x10
    P.data[0] = 0x30;

#if defined(KUZNECHIK) | defined(MAGMA)
    ret = kzchMgmCMAC(Km, P.data, PSize);
#endif

    return ret;
}
*/

uint128_256_t aes128Enc(uint128_256_t key, uint128_256_t data) {
#if defined(AES128) | defined(AES256)
    struct AES_ctx _key;
    //AES_KEY _key;
    uint128_256_t ret;
    memcpy(ret.data, data.data, sizeof(data.data));
    uint128_256_t iv = {0};

    AES_init_ctx_iv(&_key, key.data, iv.data);
    AES_CTR_xcrypt_buffer(&_key, ret.data, sizeof(ret.data));
    return ret;
#else
    return {0};
#endif
}

uint128_256_t aesCTR(uint128_256_t key, iv_t iv, uint128_256_t data) {
    return aesCTR(key, iv, data.data, sizeof (data.data));
}

uint128_256_t aesCTR(uint128_256_t key, iv_t iv, uint8_t* data, size_t size) {
#if defined(AES128) | defined(AES256)
    struct AES_ctx _key;
    uint128_256_t ret;
    memcpy(ret.data, data, size);
    AES_init_ctx_iv(&_key, key.data, (uint8_t*)&iv);
    AES_CTR_xcrypt_buffer(&_key, ret.data, size);

    return ret;
#else
    return {0};
#endif
}

uint128_256_t aesECB(uint128_256_t key, uint128_256_t data) {
#if defined(AES128) | defined(AES256)

    struct AES_ctx _key;
    uint128_256_t ret;
    memcpy(ret.data, data.data, sizeof(ret.data));
    AES_init_ctx(&_key, key.data);
    AES_ECB_encrypt(&_key, ret.data);


    return ret;
#else
    return {0};
#endif
}

uint24a_t aesCMAC(uint128_256_t key, uint8_t* data, size_t size) {
#if defined(AES128) | defined(AES256)
    return {0};
#else
    return {0};
#endif
}

uint128_256_t kzchMgmCTR(uint128_256_t key, iv_t iv, uint128_256_t data) {
    return kzchMgmCTR(key, iv, data.data, sizeof (data.data));
}

uint128_256_t kzchMgmCTR(uint128_256_t key, iv_t iv, uint8_t* data, size_t size) {
#if defined(KUZNECHIK) | defined(MAGMA)
    struct bckey bkey;
    int error;
    uint128_256_t ret;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
        return {0};
    }
    if(( error = ak_bckey_set_key( &bkey, key.data, sizeof( key.data))) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
        return {0};
      }

    ak_bckey_ctr(&bkey, data, ret.data, size, &iv, sizeof(iv));
    return ret;
#else
    return {0};
#endif
}

uint128_256_t kzchMgmECB(uint128_256_t key, uint128_256_t data) {
#if defined(KUZNECHIK) | defined(MAGMA)
    struct bckey bkey;
    int error;
    uint128_256_t ret;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
        return {0};
    }
    if(( error = ak_bckey_set_key( &bkey, key.data, sizeof( key.data))) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
        return {0};
      }

    ak_bckey_encrypt_ecb(&bkey, data.data, ret.data, sizeof(ret.data));
    return ret;
#else
    return {0};
#endif
}

uint24a_t kzchMgmCMAC(uint128_256_t key, uint8_t* data, size_t size) {
#if defined(KUZNECHIK) | defined(MAGMA)
    struct bckey bkey;
    int error;
    uint24a_t ret;

#ifdef KUZNECHIK
    if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
#else
    if(( error = ak_bckey_create_magma( &bkey )) != ak_error_ok ) {
#endif
        ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
        return {0};
    }
    if(( error = ak_bckey_set_key( &bkey, key.data, sizeof( key.data))) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong creation of test key" );
        return {0};
      }

    ak_bckey_cmac(&bkey, data, size, ret.data, sizeof(ret));
    return ret;
#else
    return {0};
#endif
}

uint128_256_t encECB(uint128_256_t key, uint128_256_t data) {
    uint128_256_t ret;

#if defined(AES128)
    ret = aesECB(key, data);//aes128Enc(Ka, tmp);
#endif

#if defined(KUZNECHIK) | defined(MAGMA)
    ret = kzchMgmECB(key, data);
#endif

    return ret;
}

uint128_256_t encCTR(uint128_256_t key, iv_t iv, uint128_256_t data) {
    uint128_256_t ret;

#if defined(AES128)
    ret = aesCTR(key, iv, data);
#endif
#if defined(KUZNECHIK) | defined(MAGMA)
    ret = kzchMgmCTR(key, iv, data);
#endif

    return ret;
}
