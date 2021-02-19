#include <iostream>
#include <time.h>
#include <unistd.h>

#include <OpenUNBDecrypterHL.h>
#include <OpenUNBEncrypterHL.h>
#include <OpenUNBConsts.h>

using namespace std;

std::string resToStr(OpenUNB::processingResult_t r) {
    switch (r) {
        case OpenUNB::processingResult_t::ACTIVATED:
            return std::string("ACTIVATED");
        break;
        case OpenUNB::processingResult_t::ADDR_NOT_FOUND:
            return std::string("ADDR_NOT_FOUND");
        break;
        case OpenUNB::processingResult_t::BAD_Na:
            return std::string("BAD_Na");
        break;
        case OpenUNB::processingResult_t::OK:
            return std::string("OK");
        break;
        case OpenUNB::processingResult_t::BAD_MIC:
            return std::string("BAD_MIC");
        break;

        default:
            return std::string("UKN state");
        break;
    }
}

int main() {
#if defined(AES128)
    std::cout << "AES128" << std::endl;
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

    srand(time(0));
    uint8_t DevID[] = {0x21, 0x01, 0x01, 0x15, 0x66};
    encryptInitData initData;
    initData.DevID = DevID;
    initData.DevID_len = sizeof(DevID);
    initData.K0 = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 , 0x7 , 0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF };
    initData.Na = 1;
    initData.Ne = { 0x0 };
    uint16_t payload2 = 0x1182;
    uint48a_t payload6 = {0x11, 0xDA, 0x01, 0xFF, 0x84, 0x55};

    init();

    time_t startTime = time(0);

    std::cout << "Inited data" << std::endl;
    std::cout << " Curret time: " << startTime << std::endl;
    std::cout << " DevID: ";
    for (int i = 0; i < initData.DevID_len; i++) {
        printf("%.2X", initData.DevID[i]);
    }
    std::cout << std::endl;

    std::cout << " K0: ";
    for (int i = 0; i < sizeof(initData.K0.data); i++) {
        printf("%.2X", initData.K0.data[i]);
    }
    std::cout << std::endl;

    std::cout << " Na: " << initData.Na << std::endl;

    std::cout << " Ne: ";
    for (int i = 0; i < sizeof(initData.Ne.data); i++) {
        printf("%.2X", initData.Ne.data[i]);
    }
    std::cout << std::endl;

    std::cout << " Payload 16 bit: " << std::hex << payload2 << std::endl;

    std::cout << " Payload 48 bit: ";
    for (int i = 0; i < sizeof(payload6.data); i++) {
        printf("%.2X", payload6.data[i]);
    }
    std::cout << std::endl;


    //////////////////////////////////////////////////////////////////////////////////////////////////
    std::cout << std::endl << "Generated data" << std::endl;
    uint128_256_t Ka = getKa(initData.K0, initData.Na);
    std::cout << " Ka: ";
    for (int i = 0; i < sizeof(Ka.data); i++) {
        printf("%.2X", Ka.data[i]);
    }
    std::cout << std::endl;


    uint24a_t DevAddr = getDevAddr(Ka, initData.Ne);
    std::cout << " DevAddr: ";
    for (int i = 0; i < sizeof(DevAddr.data); i++) {
        printf("%.2X", DevAddr.data[i]);
    }
    std::cout << std::endl;


    uint128_256_t Km = getKm(Ka, initData.Ne);
    std::cout << " Km: ";
    for (int i = 0; i < sizeof(Km.data); i++) {
        printf("%.2X", Km.data[i]);
    }
    std::cout << std::endl;


    uint128_256_t Ke = getKe(Ka, initData.Ne);
    std::cout << " Ke: ";
    for (int i = 0; i < sizeof(Ke.data); i++) {
        printf("%.2X", Ke.data[i]);
    }
    std::cout << std::endl;


    uint16_t MacPayload2 = cryptoMacPayload16(payload2, Ke, 0);
    std::cout << " MacPayload 16 bit: " << std::hex << MacPayload2 << std::endl;


    uint48a_t MacPayload6 = cryptoMacPayload48(payload6, Ke, 0);
    std::cout << " MacPayload 48 bit: ";
    for (int i = 0; i < sizeof(MacPayload6.data); i++) {
        printf("%.2X", MacPayload6.data[i]);
    }
    std::cout << std::endl;


    uint24a_t MIC16 = getMIC16(Km, DevAddr, MacPayload2, 0);
    std::cout << " MIC 16 bit: ";
    for (int i = 0; i < sizeof(MIC16.data); i++) {
        printf("%.2X", MIC16.data[i]);
    }
    std::cout << std::endl;


    uint24a_t MIC48 = getMIC48(Km, DevAddr, MacPayload6, 0);
    std::cout << " MIC 48 bit: ";
    for (int i = 0; i < sizeof(MIC48.data); i++) {
        printf("%.2X", MIC48.data[i]);
    }
    std::cout << std::endl;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    std::cout << std::endl << "High level encrypter" << std::endl;


    OpenUNB::Encrypter enc(initData);

    std::vector<uint8_t> dIn16(2);
    memcpy(dIn16.data(), &payload2, 2);

    std::vector<uint8_t> dIn48(6);
    memcpy(dIn48.data(), payload6.data, 6);

    std::cout << " Epoch: " << enc.getEpoch() << std::endl;
    std::cout << " Msg number: " << enc.getMsgNumber() << std::endl;
    std::cout << " Reset time..." << std::endl;
    enc.setStartTime(startTime);
    enc.setTime(startTime);
    std::cout << " Epoch: " << enc.getEpoch() << std::endl;
    std::cout << " Msg number: " << enc.getMsgNumber() << std::endl;

    std::vector<uint8_t> encData16 = enc.encrypt(dIn16);
    std::vector<uint8_t> encData48 = enc.encrypt(dIn48);
    std::vector<uint8_t> actReq = enc.activateMsg();

    std::cout << " Activation request: " ;
    for (int i=0; i<actReq.size(); i++) {
        printf("%.2X", actReq[i]);
        if (i == 2 || i == 4)
            std::cout << " ";
    }
    std::cout << std::endl;

    std::cout << " Full data 16: " ;
    for (int i=0; i<encData16.size(); i++) {
        printf("%.2X", encData16[i]);
        if (i == 2 || i == 4)
            std::cout << " ";
    }
    std::cout << std::endl;

    std::cout << " Full data 48: " ;
    for (int i=0; i<encData48.size(); i++) {
        printf("%.2X", encData48[i]);
        if (i == 2 || i == 8)
            std::cout << " ";
    }
    std::cout << std::endl;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    std::cout << std::endl << "High level decrypter" << std::endl;

    std::vector<OpenUNB::DevID_t> devs(3);

    devs[0].DevID = new uint8_t[initData.DevID_len];
    memcpy(devs[0].DevID, initData.DevID, initData.DevID_len);
    devs[0].DevID_len = initData.DevID_len;
    devs[0].K0 = initData.K0;

    devs[1].DevID_len = 6;
    devs[1].DevID = new uint8_t[devs[1].DevID_len];
    devs[2].DevID_len = 7;
    devs[2].DevID = new uint8_t[devs[2].DevID_len];

    OpenUNB::Decrypter decr(devs);
    std::cout << " Activated dev num: " << decr.getActivanetdNum() << "/" << decr.getNonActivanetdNum() << std::endl;

    std::cout << " Get msg (activate): " << resToStr(decr.processMsg(actReq, startTime)) << std::endl;

    std::cout << " Activated dev num: " << decr.getActivanetdNum() << "/" << decr.getNonActivanetdNum() << std::endl;

    std::cout << " Get msg (data16): " << resToStr(decr.processMsg(encData16, startTime)) << std::endl;
    std::cout << " MSG: " ;

    std::vector<uint8_t> recMsg = decr.getLastMsg();

    for (int i=0; i<recMsg.size(); i++) {
        printf("%.2X", recMsg[i]);
    }
    std::cout << std::endl;

    std::cout << " Get msg (data48): " << resToStr(decr.processMsg(encData48, startTime)) << std::endl;
    std::cout << " MSG: " ;

    recMsg = decr.getLastMsg();

    for (int i=0; i<recMsg.size(); i++) {
        printf("%.2X", recMsg[i]);
    }
    std::cout << std::endl;

    return 0;
}
