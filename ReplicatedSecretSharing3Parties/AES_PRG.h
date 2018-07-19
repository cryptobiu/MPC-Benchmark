//
// Created by liork on 30/05/16.
//

#ifndef SCAPIPRG_PRG_HPP
#define SCAPIPRG_PRG_HPP


#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "aes_locl.h"

extern unsigned int OPENSSL_ia32cap_P[];
# define AESNI_CAPABLE (OPENSSL_ia32cap_P[1]&(1<<(57-32)))

using namespace std;

typedef unsigned char byte;

#define DEFAULT_CACHE_SIZE 11000*8

class PRG
{

private:
    PRG();
    PRG(byte *key, byte *iv,int cacheSize=DEFAULT_CACHE_SIZE);

public:
    static PRG& instance();
    ~PRG();

    uint32_t getRandom();


private:
    void checkAESNI();
     byte *getRandomBytes();
     void prepare(int isPlanned = 1);


    static unsigned char m_defaultkey[16];
    static unsigned char m_defaultiv[16];

    EVP_CIPHER_CTX m_enc;

    const byte* m_key;

    int m_cacheSize;

    byte *m_cachedRandoms;

    const byte *m_iv;

    byte* m_ctr;

    unsigned long m_ctr_count = 0;

    int m_cachedRandomsIdx;

    int m_idx;

    uint32_t *m_pIdx;
    uint32_t m_u1;
    uint32_t m_u2;
    uint32_t m_u3;
    uint32_t m_u4;


    static PRG *_prg;
};

class UnsupportAESNIException : public exception
{

public:
    virtual const char* what() const throw();
};

#endif //SCAPIPRG_PRG_HPP
