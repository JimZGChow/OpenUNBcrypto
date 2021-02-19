#include "OpenUNBDecrypterHL.h"

namespace OpenUNB {

Decrypter::Decrypter(const std::vector<DevID_t>& DevList) {
    devListNotActivated.resize(0);
    devListActivated.resize(0);

    for (auto dev : DevList) {
        DevInfo_t devInfo;
        devInfo.DevID = new uint8_t[dev.DevID_len];

        memcpy(devInfo.DevID, dev.DevID, dev.DevID_len);
        devInfo.DevIDLen = dev.DevID_len;

        devInfo.activated = false;

        devInfo.DevAddr1.ud = crc24(devInfo.DevID, devInfo.DevIDLen);

        devInfo.K0 = dev.K0;
        devInfo.Na = 0;

        devListNotActivated.push_back(devInfo);
    }
}

Decrypter::~Decrypter() {
    for (auto dev : devListNotActivated) {
        delete [] dev.DevID;
    }

    for (auto dev : devListActivated) {
        delete [] dev.DevID;
    }
}

processingResult_t Decrypter::processMsg(const std::vector<uint8_t>& data, time_t timestamp) {
    processingResult_t ret = processingResult_t::ADDR_NOT_FOUND;

    msg_t msg;
    msg.is16Bit = data.size() == 8;
    memcpy(msg.devAddr.data, data.data(), sizeof (msg.devAddr.data));
    if (msg.is16Bit)
        memcpy(&msg.payload16, data.data() + sizeof (msg.devAddr.data), sizeof(msg.payload16));
    else
        memcpy(&msg.payload48, data.data() + sizeof (msg.devAddr.data), sizeof(msg.payload48));

    memcpy(msg.MIC.data, data.data() + data.size() - sizeof(msg.MIC.data), sizeof(msg.MIC.data));

    if (data.size() == 8) {
        for (int i=0; i < devListNotActivated.size(); i++) {
            auto dev =  devListNotActivated[i];

            if (msg.devAddr.ud == dev.DevAddr1.ud) {
                ret = activate(msg, dev);
                if (ret == OK) {
                    dev.activationTime = timestamp;
                    devListActivated.push_back(dev);
                    devListNotActivated.erase(devListNotActivated.begin() + i);
                    i--;
                }
            }
        }
    }

    for (auto dev : devListActivated) {
        if (msg.devAddr.ud == dev.DevAddr1.ud) {
            ret = encodeMsg(msg, dev, timestamp);
        } else if (msg.devAddr.ud == dev.DevAddr2.ud) {
            ////////////////////////////////////////////////
        }
    }

    return ret;
}

void Decrypter::nextEpoch(DevInfo_t& dev) {
    dev.DevAddr1 = dev.DevAddr2;
    dev.Ne1 = dev.Ne2;
    dev.Ke1 = dev.Ke2;
    dev.Km1 = dev.Km2;

    dev.Ne2.ud = (dev.Ne2.ud + 1) & 0xFFFFFF;
    dev.DevAddr2 = getDevAddr(dev.Ka, dev.Ne2);
    dev.Ke2 = getKe(dev.Ka, dev.Ne2);
    dev.Km2 = getKm(dev.Ka, dev.Ne2);
}

std::vector<uint8_t> Decrypter::getLastMsg() {
    return lastMsg;
}

processingResult_t Decrypter::encodeMsg(const msg_t& data, DevInfo_t& dev, time_t timestamp) {
    uint16_t Nn = S2M((timestamp - dev.activationTime) % EPOCH_DURATION);
    processingResult_t ret = BAD_MIC;

    for (int i=0; i<3; i++) {
        uint24a_t genMIC;
        if (data.is16Bit)
           genMIC = getMIC16(dev.Km1, dev.DevAddr1, data.payload16, Nn - 1 + i);
        else
           genMIC = getMIC48(dev.Km1, dev.DevAddr1, data.payload48, Nn - 1 + i);

        if (genMIC.ud == data.MIC.ud) {
            ret = OK;
            if (data.is16Bit) {
                lastMsg.resize(2);
                uint16_t payload = cryptoMacPayload16(data.payload16, dev.Ke1, Nn - 1 + i);

                lastMsg[1] = payload & 0xFF;
                lastMsg[0] = (payload >> 8) & 0xFF;
            } else {
                lastMsg.resize(6);
                uint48a_t payload = cryptoMacPayload48(data.payload48, dev.Ke1, Nn - 1 + i);
                memcpy(lastMsg.data(), payload.data, sizeof (payload.data));
            }
        }
    }

    return ret;
}

processingResult_t Decrypter::activate(const msg_t& data, DevInfo_t& dev) {
    uint16_t Na = data.payload16;

    if (dev.Na >= Na) {
        return BAD_Na;
    }

    dev.Ka = getKa(dev.K0, Na);
    dev.Na = Na;
    dev.Ne1 = {0};
    dev.Km1 = getKm(dev.Ka, dev.Ne1);
    dev.activationTime = time(nullptr);

    uint24a_t MICGen = getMIC16(dev.Km1, data.devAddr, Na, 0);

    if (MICGen.ud == data.MIC.ud) {
        dev.DevAddr1 = getDevAddr(dev.Ka, dev.Ne1);

        dev.Ne2.ud = (dev.Ne1.ud + 1) & 0xFFFFFF;
        dev.DevAddr2 = getDevAddr(dev.Ka, dev.Ne2);

        dev.Ke1 = getKe(dev.Ka, dev.Ne1);
        dev.Ke2 = getKe(dev.Ka, dev.Ne2);
        dev.Km2 = getKm(dev.Ka, dev.Ne2);

        return OK;
    }
    else
        return BAD_MIC;
}

int Decrypter::getActivanetdNum() {
    return devListActivated.size();
}

int Decrypter::getNonActivanetdNum() {
    return devListNotActivated.size();
}

void Decrypter::updateTime(time_t t) {

}

}
