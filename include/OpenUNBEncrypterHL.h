#include <OpenUNBEncrypterLL.h>
#include <OpenUNBConsts.h>

void initEncrypter(struct encrypt_data_t* enc_data);

void encodeActivateMsg(struct encrypt_data_t* enc_data, uint8_t* out, time_t time);

int encodeData(struct encrypt_data_t* enc_data, uint8_t* in, uint8_t* out, size_t size, time_t time);
