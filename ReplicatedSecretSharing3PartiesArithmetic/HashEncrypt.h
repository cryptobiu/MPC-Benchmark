#ifndef INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHENCRYPT_HPP
#define INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHENCRYPT_HPP

#include "HashAbstract.h"

/**
 * Class that wraps GCM-128 procedure to hash arrays.
 */
class HashEncrypt : public HashAbstract
{
public:
    // key - 128-bit, iv changed size.
    HashEncrypt(const unsigned char *key, const unsigned char *iv,
                size_t ivSizeBytes);
    ~HashEncrypt();
    void hashUpdate(unsigned char *in, int inSizeBytes) override;
    void hashFinal(unsigned char *out, unsigned int *outSizeBytes) override;
//    void hashReset() override;


private:
    int _finalSizeBytes = 16;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#else
    EVP_CIPHER_CTX *_ctx;
#endif
    unsigned char _key[16]; // 128-bit key
    unsigned char *_iv;     // initialization vector
    int _unusedOutl;

};


#endif //INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHENCRYPT_HPP