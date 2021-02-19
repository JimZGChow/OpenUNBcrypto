#ifndef OPENUNBDECRYPTERHL_H
#define OPENUNBDECRYPTERHL_H

#include <vector>
#include <string>

#include "crc24.h"
#include "OpenUNBEncrypterLL.h"
#include "OpenUNBConsts.h"

namespace OpenUNB {

struct DevID_t {
    uint8_t* DevID;
    uint8_t DevID_len;
    uint128_256_t K0;
};

enum processingResult_t {
    ADDR_NOT_FOUND = -1,
    BAD_Na = -2,
    BAD_MIC = -3,
    OK = 1,
    ACTIVATED = 2
};

struct DevInfo_t {
    uint8_t* DevID;
    uint8_t DevIDLen;
    uint128_256_t K0;
    uint16_t Na;

    uint16_t Nn;

    uint24a_t Ne1;
    uint24a_t Ne2;
    uint24a_t DevAddr1;
    uint24a_t DevAddr2;
    uint128_256_t Ke1;
    uint128_256_t Ke2;
    uint128_256_t Km1;
    uint128_256_t Km2;

    uint128_256_t Ka;

    time_t activationTime;
    bool activated;
};

struct msg_t {
    uint24a_t devAddr;
    uint48a_t payload48;
    uint16_t payload16;
    uint24a_t MIC;
    bool is16Bit; // true - payload 16 bit, false - paqload 48 bit
};


class Decrypter {
public:
    Decrypter(const std::vector<DevID_t>& DevList);
    ~Decrypter();

    processingResult_t processMsg(const std::vector<uint8_t>& data, time_t timestamp);
    void updateTime(time_t t);

    int getActivanetdNum();
    int getNonActivanetdNum();
    std::vector<uint8_t> getLastMsg();
private:
    processingResult_t activate(const msg_t& data, DevInfo_t& dev);
    processingResult_t encodeMsg(const msg_t& data, DevInfo_t& dev, time_t timestamp);

    void nextEpoch(DevInfo_t& dev);

    std::vector<uint8_t> lastMsg;
    std::vector<DevInfo_t> devListNotActivated;
    std::vector<DevInfo_t> devListActivated;
};


}; // namespace OpenUNB
#endif // OPENUNBDECRYPTERHL_H
