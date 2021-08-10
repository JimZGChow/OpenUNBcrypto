#include <time.h>
#include <unistd.h>

#include <OpenUNBEncrypterHL.h>
#include <OpenUNBConsts.h>
#include <OpenUNBEncrypterLL.h>


int main() {
#if defined(AES128)
    printf("AES128");
#elif defined(AES256)
    std::cout << "AES256" << std::endl;
#elif defined(KUZNECHIK)
    std::cout << "KUZNECHIK" << std::endl;
#elif defined(MAGMA)
    std::cout << "MAGMA" << std::endl;
#else
    std::cout << "Run cmake with flag:" << std::endl;
    std::cout << "   -DAES128 for AES128" << std::endl;
    std::cout << "   -DAES256 for AES256" << std::endl;
    std::cout << "   -DKUZNECHIK for KUZNECHIK" << std::endl;
    std::cout << "   -DMAGMA for MAGMA" << std::endl;
#endif
    uint8_t K0[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 , 0x7 , 0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF , 0x0};

    srand(time(0));
    uint8_t DevID[] = {0x21, 0x01, 0x01, 0x15, 0x66};
    struct encrypt_data_t initData;
    initData.DevID = DevID;
    initData.DevID_len = sizeof(DevID);
    initData.Na = 1;
    initData.Ne = 0;

    uint8_t payload2[] = {0x11, 0x82};
    uint8_t payload6[] = {0x11, 0xDA, 0x01, 0xFF, 0x84, 0x55};

    memcpy(initData.K0, K0, sizeof(K0));

    //init_encrypter();

    time_t startTime = time(0);

    printf("Inited data\n");
    printf(" Curret time: %u\n", startTime);
    printf(" DevID: ");
    for (int i = 0; i < initData.DevID_len; i++) {
        printf("%.2X", initData.DevID[i]);
    }
    printf("\n");

    printf(" K0: ");
    for (int i = 0; i < sizeof(initData.K0); i++) {
        printf("%.2X", initData.K0[i]);
    }
    printf("\n");

    printf(" Na: %.4X\n", initData.Na);
    printf(" Na: %.6X\n", initData.Ne);

    printf(" Payload 16 bit: ");
    for (int i = 0; i < sizeof(payload2); i++) {
        printf("%.2X", payload2[i]);
    }
    printf("\n");


    printf(" Payload 48 bit: ");
    for (int i = 0; i < sizeof(payload6); i++) {
        printf("%.2X", payload6[i]);
    }
    printf("\n");


    //////////////////////////////////////////////////////////////////////////////////////////////////
    printf("\nGenerated data\n");

    getKa(initData.K0, initData.Na, initData.Ka);
    printf(" Ka: ");
    for (int i = 0; i < sizeof(initData.Ka); i++) {
        printf("%.2X", initData.Ka[i]);
    }
    printf("\n");


    uint32_t DevAddr = getDevAddr(initData.Ka, initData.Ne);
    printf(" DevAddr: 0x%X\n", DevAddr);

    getKm(initData.Ka, initData.Ne, initData.Km);
    printf(" Km: ");
    for (int i = 0; i < sizeof(initData.Km); i++) {
        printf("%.2X", initData.Km[i]);
    }
    printf("\n");


    getKe(initData.Ka, initData.Ne, initData.Ke);
    printf(" Ke: ");
    for (int i = 0; i < sizeof(initData.Ke); i++) {
        printf("%.2X", initData.Ke[i]);
    }
    printf("\n");


    uint8_t MacPayload2[2];
    cryptoMacPayload(payload2, MacPayload2, 2, initData.Ke, 0);
    printf(" MacPayload 16 bit: ");
    for (int i = 0; i < sizeof(MacPayload2); i++) {
        printf("%.2X", MacPayload2[i]);
    }
    printf("\n");


    uint8_t MacPayload6[6];
    cryptoMacPayload(payload6, MacPayload6, 6, initData.Ke, 0);
    printf(" MacPayload 48 bit: ");
    for (int i = 0; i < sizeof(MacPayload6); i++) {
        printf("%.2X", MacPayload6[i]);
    }
    printf("\n");

    uint8_t MIC16[3];
    getMIC(initData.Km, DevAddr, MacPayload2, MIC16, 2, 0);
    printf(" MIC 16 bit: ");
    for (int i = 0; i < sizeof(MIC16); i++) {
        printf("%.2X", MIC16[i]);
    }
    printf("\n");

    uint8_t MIC48[3];
    getMIC(initData.Km, DevAddr, MacPayload6, MIC48, 6, 0);
    printf(" MIC 48 bit: ");
    for (int i = 0; i < sizeof(MIC48); i++) {
        printf("%.2X", MIC48[i]);
    }
    printf("\n");

    //////////////////////////////////////////////////////////////////////////////////////////////////
    printf("\nEncrypting\n");

    initEncrypter(&initData);
    uint8_t act_msg[3 + 2 + 3];

    encodeActivateMsg(&initData, act_msg, startTime);
    printf(" Msg of activation: ");
    for (int i = 0; i < sizeof(act_msg); i++) {
        printf("%.2X", act_msg[i]);
    }
    printf("\n");

    uint8_t enc_msg16[3 + 2 + 3];
    int ret = encodeData(&initData, payload2, enc_msg16, 2, startTime);

    if (ret < 0) {
        printf(" encodeData Error\n");
    } else {
        printf(" Encoded msg 16 bit: ");
        for (int i = 0; i < sizeof(enc_msg16); i++) {
            printf("%.2X", enc_msg16[i]);
        }
        printf("\n");
    }

    uint8_t enc_msg48[3 + 6 + 3];
    ret = encodeData(&initData, payload6, enc_msg48, 6, startTime + 60000);

    if (ret < 0) {
        printf(" encodeData Error\n");
    } else {
        printf(" Encoded msg 48 bit: ");
        for (int i = 0; i < sizeof(enc_msg48); i++) {
            printf("%.2X", enc_msg48[i]);
        }
        printf("\n");
    }
}
