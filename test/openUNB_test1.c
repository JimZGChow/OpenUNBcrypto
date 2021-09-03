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

void printArrayEndian(uint8_t* arr, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%.2X", arr[i]);
    }
    printf("\n");
}

void testNa() {
    struct encrypt_data_t initData;

    printf("Init data: \n");

    for (int i=0; i<sizeof(initData.DevID); i++) {
        initData.DevID[i] = rand() & 0xFF;
    }

    printf(" DevID: 0x");
    printArrayEndian(initData.DevID, sizeof(initData.DevID));

    for (int i=0; i<sizeof(initData.K0); i++) {
        initData.K0[i] = rand() & 0xFF;
    }

    printf(" K0: 0x");
    printArrayEndian(initData.K0, sizeof(initData.K0));


    printf("\n");

    initData.Na = rand() & 0x7FFF;
    printf("Na = 0x%.4X\n", initData.Na );

    initEncrypter(&initData);
    uint8_t act_msg[3 + 2 + 3] = {0};

    encodeActivateMsg(&initData, act_msg, 0);
    printf(" Msg of activation: 0x");
    printArray(act_msg, sizeof(act_msg));


    initData.Na = initData.Na + 1;
    printf("Na = 0x%.4X\n", initData.Na);

    initEncrypter(&initData);

    encodeActivateMsg(&initData, act_msg, 0);
    printf(" Msg of activation: 0x");
    printArray(act_msg, sizeof(act_msg));
}

void testPacket() {
    struct encrypt_data_t initData;
    initData.Na = rand() % 0x7FFF;
    initData.Ne = rand() % 0xFFFFFF;

    uint8_t payload2[2];
    uint8_t payload6[6];

    for (int i=0; i<sizeof(initData.DevID); i++) {
        initData.DevID[i] = rand() & 0xFF;
    }

    for (int i=0; i<sizeof(initData.K0); i++) {
        initData.K0[i] = rand() & 0xFF;
    }

    for (int i=0; i<sizeof(payload2); i++) {
        payload2[i] = rand() & 0xFF;
    }

    for (int i=0; i<sizeof(payload6); i++) {
        payload6[i] = rand() & 0xFF;
    }

    //init_encrypter();

    time_t startTime = time(0);

    printf("Inited data\n");
    printf(" Curret time: %u\n", startTime);
    printf(" DevID: 0x");
    printArrayEndian(initData.DevID, sizeof(initData.DevID));

    printf(" K0: 0x");
    printArrayEndian(initData.K0, sizeof(initData.K0));

    printf(" Na: 0x%.4X\n", initData.Na);
    printf(" Ne: 0x%.6X\n", initData.Ne);

    printf(" Payload 16 bit: 0x");
    printArrayEndian(payload2, sizeof(payload2));

    printf(" Payload 48 bit: 0x");
    printArrayEndian(payload6, sizeof(payload6));

    //////////////////////////////////////////////////////////////////////////////////////////////////
    printf("\nGenerated data\n");

    getKa(initData.K0, initData.Na, initData.Ka);
    printf(" Ka: 0x");
    printArrayEndian(initData.Ka, sizeof(initData.Ka));

    uint32_t DevAddr = getDevAddr(initData.Ka, initData.Ne);
    printf(" DevAddr: 0x%X\n", DevAddr);

    getKm(initData.Ka, initData.Ne, initData.Km);
    printf(" Km: 0x");
    printArrayEndian(initData.Km, sizeof(initData.Km));

    getKe(initData.Ka, initData.Ne, initData.Ke);
    printf(" Ke: 0x");
    printArrayEndian(initData.Ke, sizeof(initData.Ke));

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
}

void printArray1(uint8_t* arr, size_t size) {
    for (int i = size - 1; i >= 0; i--) {
        printf("%.2X", arr[i]);
    }
}

int main() {
    int b = 0x01020304;
    printArray(&b, sizeof(b));

    printf("------------------- Na test ------------------- \n");
    printf("-------------------    #1   ------------------- \n");
    testNa();
    printf("\n");
    printf("-------------------    #2   ------------------- \n");
    testNa();
    printf("\n\n");
    printf("----------------- Packet test ----------------- \n");
    printf("-------------------    #1   ------------------- \n");
    testPacket();
    printf("\n");
    printf("-------------------    #2   ------------------- \n");
    testPacket();
}
