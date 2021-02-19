### Introducton

Its a simple OpenUNB library with crypto protocol.

### Dependencies

- cmake
- libakrypt (for Magma or Kuznechik) https://github.com/axelkenzo/libakrypt-0.x

### Install

```
git clone https://github.com/bolt5/OpenUNBcrypto.git
cd OpenUNBcrypto/
mkdir build
cd build/
cmake ..
make
sudo make install
```

For the choose crypto algorithm use:
For AES128
```
cmake -DAES128=ON
```

For MAGMA
```
cmake -DMAGMA=ON
```

For KUZNECHIK
```
cmake -DKUZNECHIK=ON
```

