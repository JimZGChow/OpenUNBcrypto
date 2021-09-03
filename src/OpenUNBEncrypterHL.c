#include <OpenUNBEncrypterHL.h>


void initEncrypter(struct encrypt_data_t* enc_data) {
    getKa(enc_data->K0, enc_data->Na, enc_data->Ka);

    enc_data->Ne_last = 0;
    enc_data->Nn = 0;
    enc_data->Nn_last = 0;
}

void encodeActivateMsg(struct encrypt_data_t* enc_data, uint8_t* out, time_t time) {

    enc_data->init_time = MS2S(time); // to sec
    enc_data->Ne = 0;
    getKe(enc_data->Ka, enc_data->Ne, enc_data->Ke);
    getKm(enc_data->Ka, enc_data->Ne, enc_data->Km);

    enc_data->dev_addr = getDevAddr(enc_data->Ka, enc_data->Ne);

    uint32_t devAddr24 = 0;
    uint8_t payload[2] = {0};
    uint16_t NaNet = htons(enc_data->Na);
    memcpy(payload, &NaNet, 2);
    uint8_t MIC[3] = {0};

    devAddr24 = crc24(enc_data->DevID, sizeof(enc_data->DevID));

    uint32_t devAddr24Net = htonl(devAddr24);
    getMIC(enc_data->Km, devAddr24, payload, MIC, 2, 0);


#ifndef AK_BIG_ENDIAN
    devAddr24Net = devAddr24Net >> 8;
#endif

    memcpy(out, MIC, sizeof(MIC));
    //memcpy(out + 3, payload, 2);
    out[3] = (NaNet >> 8) & 0xFF;
    out[4] = NaNet & 0xFF;
    out[5] = (devAddr24Net >> 16) & 0xFF;
    out[6] = (devAddr24Net >> 8) & 0xFF;
    out[7] = devAddr24Net & 0xFF;
    //memcpy(out + 2 + sizeof (MIC), &devAddr24Net, 3);
}

int encodeData(struct encrypt_data_t* enc_data, uint8_t* in, uint8_t* out, size_t size, time_t time) {
    if (size != 2 && size != 6)
        return -1;

    uint32_t newNe = 0;
    uint8_t payload[6]= {0};
    int8_t MIC[3] = {0};

    newNe = (MS2S(time) - enc_data->init_time) / EPOCH_DURATION;

    if (newNe != enc_data->Ne) {
        enc_data->Ne = newNe;

        getKe(enc_data->Ka, enc_data->Ne, enc_data->Ke);
        getKm(enc_data->Ka, enc_data->Ne, enc_data->Km);
        enc_data->dev_addr = getDevAddr(enc_data->Ka, enc_data->Ne);
    }

    enc_data->Nn = S2M((MS2S(time) - enc_data->init_time) % EPOCH_DURATION);

    if (enc_data->Nn == enc_data->Nn_last && enc_data->Ne == enc_data->Ne_last) {
        enc_data->Nn++;
    }else if (enc_data->Nn + 1 == enc_data->Nn_last && enc_data->Ne == enc_data->Ne_last) {
        return -1;
    }

    enc_data->Nn_last = enc_data->Nn;
    enc_data->Ne_last = enc_data->Ne;

    cryptoMacPayload(in, payload, size, enc_data->Ke, enc_data->Nn);

    getMIC(enc_data->Km, enc_data->dev_addr, payload, MIC, size, enc_data->Nn);

    uint32_t devAddr24Net = htonl(enc_data->dev_addr);

#ifndef AK_BIG_ENDIAN
    devAddr24Net = devAddr24Net >> 8;
#endif

    memcpy(out, MIC, sizeof (MIC));
    memcpy(out + sizeof (MIC), payload, size);
    out[5] = (devAddr24Net >> 16) & 0xFF;
    out[6] = (devAddr24Net >> 8) & 0xFF;
    out[7] = devAddr24Net & 0xFF;

    return 0;
}
