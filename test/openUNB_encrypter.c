#include <time.h>
#include <unistd.h>

#include <OpenUNBEncrypterHL.h>
#include <OpenUNBConsts.h>
#include <OpenUNBEncrypterLL.h>

void printArray(uint8_t* arr, size_t size) {
    for (int i = size - 1; i >= 0; i--) {
        printf("%.2X", arr[i]);
    }
    printf("\n");
}

void printArray1(uint8_t* arr, size_t size) {
    for (int i = size - 1; i >= 0; i--) {
        printf("%.2X", arr[i]);
    }
}

int main() {
#if defined(AES128)
    printf("AES128");
#elif defined(AES256)
    std::cout << "AES256" << std::endl;
#elif defined(KUZNECHIK)
    std::cout << "KUZNECHIK" << std::endl;
#elif defined(MAGMA)
    printf("MAGMA\n");
#else
    std::cout << "Run cmake with flag:" << std::endl;
    std::cout << "   -DAES128 for AES128" << std::endl;
    std::cout << "   -DAES256 for AES256" << std::endl;
    std::cout << "   -DKUZNECHIK for KUZNECHIK" << std::endl;
    std::cout << "   -DMAGMA for MAGMA" << std::endl;
#endif

    srand(time(0));
    srand(4000);

#if defined(MAGMA) || defined(KUZNECHIK)
    uint8_t K0[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 , 0x7 , 0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF , 0x0,  0x1, 0x2, 0x3, 0x4, 0x5, 0x6 , 0x7 , 0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF , 0x0};
#else
    uint8_t K0[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 , 0x7 , 0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF , 0x0};
#endif

    for (int i=0; i< sizeof(K0); i++) {
        K0[i] = rand() & 0xFF;
    }


    uint8_t DevID[16] = {0xF2, 0xAA, 0x8F, 0x5, 0xCD, 0xfa, 0x55, 0xaa, 0xbb, 0xca};

    for (int i=0; i< sizeof(DevID); i++) {
        DevID[i] ^= K0[i];
    }

    struct encrypt_data_t initData;
    initData.Na = 77;
    initData.Ne = 533;

    uint8_t payload2[] = {0x05, 0xFF};
    uint8_t payload6[] = {0x12, 0x71, 0x01, 0xFF, 0xC3, 0xA0};

    memcpy(initData.DevID, DevID, sizeof(DevID));
    memcpy(initData.K0, K0, sizeof(K0));

    //init_encrypter();

    time_t startTime = time(0);

    printf("Inited data\n");
    printf(" Curret time: %u\n", startTime);
    printf(" DevID: 0x");
    printArray(initData.DevID, sizeof(initData.DevID));

    printf(" K0: 0x");
    printArray(initData.K0, sizeof(initData.K0));

    printf(" Na: 0x%.4X\n", initData.Na);
    printf(" Ne: 0x%.6X\n", initData.Ne);

    printf(" Payload 16 bit: 0x");
    printArray(payload2, sizeof(payload2));

    printf(" Payload 48 bit: 0x");
    printArray(payload6, sizeof(payload6));

    //////////////////////////////////////////////////////////////////////////////////////////////////
    printf("\nGenerated data\n");

    getKa(initData.K0, initData.Na, initData.Ka);
    printf(" Ka: 0x");
    printArray(initData.Ka, sizeof(initData.Ka));

    uint32_t DevAddr = getDevAddr(initData.Ka, initData.Ne);
    printf(" DevAddr: 0x%X\n", DevAddr);

    getKm(initData.Ka, initData.Ne, initData.Km);
    printf(" Km: 0x");
    printArray(initData.Km, sizeof(initData.Km));

    getKe(initData.Ka, initData.Ne, initData.Ke);
    printf(" Ke: 0x");
    printArray(initData.Ke, sizeof(initData.Ke));

    uint8_t MacPayload2[2];
    cryptoMacPayload(payload2, MacPayload2, 2, initData.Ke, 0);
    printf(" MacPayload 16 bit: 0x");
    printArray(MacPayload2, sizeof(MacPayload2));

    uint8_t MacPayload6[6];
    cryptoMacPayload(payload6, MacPayload6, 6, initData.Ke, 0);
    printf(" MacPayload 48 bit: 0x");
    printArray(payload6, sizeof(payload6));

    uint8_t MIC16[3];
    getMIC(initData.Km, DevAddr, MacPayload2, MIC16, 2, 0);
    printf(" MIC 16 bit: 0x");
    printArray(MIC16, sizeof(MIC16));

    uint8_t MIC48[3];
    getMIC(initData.Km, DevAddr, MacPayload6, MIC48, 6, 0);
    printf(" MIC 48 bit: 0x");
    printArray(MIC48, sizeof(MIC48));

    printf(" Full msg for payload 16 bit: 0x%X", DevAddr);
    printArray1(MacPayload2, sizeof(MacPayload2));
    printArray(MIC16, sizeof(MIC16));

    printf(" Full msg for payload 48 bit: 0x%X", DevAddr);
    printArray1(MacPayload6, sizeof(MacPayload6));
    printArray(MIC48, sizeof(MIC48));

    //////////////////////////////////////////////////////////////////////////////////////////////////
    printf("\nEncrypting\n");

    initEncrypter(&initData);
    uint8_t act_msg[3 + 2 + 3] = {0};

    encodeActivateMsg(&initData, act_msg, startTime);
    printf(" Msg of activation: 0x");
    printArray(act_msg, sizeof(act_msg));

    uint8_t enc_msg16[3 + 2 + 3] = {0};
    int ret = encodeData(&initData, payload2, enc_msg16, 2, startTime);

    if (ret < 0) {
        printf(" encodeData Error\n");
    } else {
        printf(" Encoded msg 16 bit: 0x");
        printArray(enc_msg16, sizeof(enc_msg16));
    }

    uint8_t enc_msg48[3 + 6 + 3] = {0};
    ret = encodeData(&initData, payload6, enc_msg48, 6, startTime + 60000);

    if (ret < 0) {
        printf(" encodeData Error\n");
    } else {
        printf(" Encoded msg 48 bit: 0x");
        printArray(enc_msg48, sizeof(enc_msg48));
    }
}
