#include <OpenUNBEncrypterHL.h>

namespace OpenUNB {

bool Encrypter::inited = false;

Encrypter::Encrypter(const uint8_t* DevID, uint8_t DevIDLen, const uint128_256_t& K0, uint16_t Na) {
    if (!inited) {
        init();
        inited = true;
    }

    _DevID = new uint8_t[DevIDLen];
    memcpy(_DevID, DevID, DevIDLen);
    _DevIDLen = DevIDLen;

    _K0 = K0;
    _Na = Na;

    _Ne = 0;
    _Nn = 0;

    setActivationNumber(_Na);

    startTime = time(NULL);
}

Encrypter::Encrypter(const uint8_t* DevID, uint8_t DevIDLen, const uint8_t* K0, uint16_t Na) {
    if (!inited) {
        init();
        inited = true;
    }

    _DevID = new uint8_t[DevIDLen];
    memcpy(_DevID, DevID, DevIDLen);
    _DevIDLen = DevIDLen;

    memcpy(_K0.data, K0, sizeof(_K0.data));
    _Na = Na;

    _Ne = 0;
    _Nn = 0;

    setActivationNumber(_Na);

    startTime = time(NULL);
}

Encrypter::Encrypter(const encryptInitData& in) {
    if (!inited) {
        init();
        inited = true;
    }

    _DevID = new uint8_t[in.DevID_len];
    memcpy(_DevID, in.DevID, in.DevID_len);
    _DevIDLen = in.DevID_len;

    _K0 = in.K0;
    _Na = in.Na;

    _Ne = 0;
    _Nn = 0;

    setActivationNumber(_Na);

    startTime = time(NULL);
}


Encrypter::~Encrypter() {
    delete [] _DevID;
}

void Encrypter::setActivationNumber(uint16_t Na) {
    _Na = Na;
    _Ka = getKa(_K0, _Na);

    setTime(_Ne);
}

void Encrypter::setStartTime(time_t time) {
    startTime = time;
}

void Encrypter::setTime(time_t time) {
    _lastNe = _Ne;
    _lastNn = _Nn;

    _Ne = (time - startTime) / EPOCH_DURATION;
    _Nn = S2M((time - startTime) % EPOCH_DURATION);
    _Ne = _Ne & 0xFFFFFF;

    if (_Ne == _lastNe && _Nn == _lastNn)
        _Nn++;

    if (_lastNe != _Ne) {
        uint24a_t Ne24;
        Ne24.ud = _Ne & 0xFFFFFF;

        _DevAddr = getDevAddr(_Ka, Ne24);
        _Km = getKm(_Ka, Ne24);
        _Ke = getKe(_Ka, Ne24);
    }
}

void Encrypter::setMsgNumber(uint16_t Nn) {
    _Nn = Nn;
}

uint16_t Encrypter::getActivationNumber() {
    return _Na;
}

uint32_t Encrypter::getEpoch() {
    return _Ne;
}

uint16_t Encrypter::getMsgNumber() {
    return _Nn;
}

std::vector<uint8_t> Encrypter::encrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> ret(0);

    uint16_t macPayload16;
    uint48a_t macPayload48;
    uint48a_t payload48;
    uint24a_t MIC;
    switch (data.size()) {
    case 2:
        ret.resize(8);

        memcpy(ret.data(), _DevAddr.data, sizeof (_DevAddr.data));

        macPayload16 = cryptoMacPayload16(*((uint16_t*)data.data()), _Ke, _Nn);
        memcpy(ret.data() + sizeof (_DevAddr.data), &macPayload16, sizeof (macPayload16));

        MIC = getMIC16(_Km, _DevAddr, macPayload16, _Nn);
        memcpy(ret.data() + sizeof (_DevAddr.data) + sizeof (macPayload16), MIC.data, sizeof (MIC));
        break;
    case 6:
        ret.resize(12);

        memcpy(ret.data(), _DevAddr.data, sizeof (_DevAddr.data));

        memcpy(payload48.data, data.data(), sizeof (payload48));
        macPayload48 = cryptoMacPayload48(payload48, _Ke, _Nn);
        memcpy(ret.data() + sizeof (_DevAddr.data), macPayload48.data, sizeof (macPayload48.data));

        MIC = getMIC48(_Km, _DevAddr, macPayload48, _Nn);
        memcpy(ret.data() + sizeof (_DevAddr.data) + sizeof (macPayload48.data), MIC.data, sizeof (MIC));
        break;
    }

    return ret;
}

std::vector<uint8_t> Encrypter::activateMsg() {
    std::vector<uint8_t> ret(8);
    uint16_t macPayload16;

    uint24a_t devAddr24 = {0};
    devAddr24.ud = crc24(_DevID, _DevIDLen);
    uint24a_t MIC;

    memcpy(ret.data(), devAddr24.data, sizeof(devAddr24.data));

    macPayload16 = _Na;
    memcpy(ret.data() + sizeof (devAddr24.data), &macPayload16, sizeof (macPayload16));

    MIC = getMIC16(_Km, devAddr24, macPayload16, 0);
    memcpy(ret.data() + sizeof (_DevAddr.data) + sizeof (macPayload16), MIC.data, sizeof (MIC.data));

    return ret;
}

};
