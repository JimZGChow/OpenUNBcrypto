#ifndef OPENUNBENCRYPTERHL_H
#define OPENUNBENCRYPTERHL_H

#include <vector>

#include "OpenUNBEncrypterLL.h"
#include "crc24.h"
#include "OpenUNBConsts.h"

#include <iostream>

namespace OpenUNB {

class Encrypter {
public:
    Encrypter(const uint8_t* DevID, uint8_t DevIDLen, const uint128_256_t& K0, uint16_t Na);
    Encrypter(const uint8_t* DevID, uint8_t DevIDLen, const uint8_t* K0, uint16_t Na);
    Encrypter(const encryptInitData& in);
    ~Encrypter();

    void setActivationNumber(uint16_t Na);
    void setStartTime(time_t time);
    void setTime(time_t time);
    void setMsgNumber(uint16_t Nn);

    uint16_t getActivationNumber();
    uint32_t getEpoch();
    uint16_t getMsgNumber();

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> activateMsg();
private:
    uint8_t* _DevID;
    uint8_t _DevIDLen;
    uint128_256_t _K0;
    uint16_t _Na;

    uint32_t _Ne;
    uint16_t _Nn;
    uint32_t _lastNe;
    uint16_t _lastNn;

    uint128_256_t _Ka;
    uint24a_t _DevAddr;
    uint128_256_t _Km;
    uint128_256_t _Ke;

    static bool inited;

    time_t startTime;


};

};
#endif // OPENUNBENCRYPTERHL_H
