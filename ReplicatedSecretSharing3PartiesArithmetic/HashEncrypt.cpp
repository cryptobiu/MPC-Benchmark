#include <cstring>
#include "HashEncrypt.h"

/**
 * CTOR. Create an object to hash arrays using GCM-128 procedure.
 * @param key 128-bit key
 * @param iv initialization vector
 * @param ivSizeBytes size in bytes of the initialization vector
 */
HashEncrypt::HashEncrypt(const unsigned char *key, const unsigned char *iv, size_t ivSizeBytes)
{
    // copy the 128-bit key
    memcpy(_key, key, 16);

    //copy the iv:
    _iv = new unsigned char[ivSizeBytes];
    memcpy(_iv, iv, ivSizeBytes);

    EVP_CIPHER_CTX_init(&_ctx);

    EVP_EncryptInit_ex(&_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL); //TODO check return value == 1

    EVP_CIPHER_CTX_ctrl(&_ctx, EVP_CTRL_GCM_SET_IVLEN, ivSizeBytes, NULL);

    EVP_EncryptInit_ex(&_ctx, NULL, NULL, _key, _iv);

}

/**
 * DTOR
 */
HashEncrypt::~HashEncrypt()
{
    EVP_CIPHER_CTX_cleanup(&_ctx);

    delete[] _iv;
    _iv = nullptr;
}

/**
 * Update the hash object with data
 * @param in data
 * @param inSizeBytes size of data in bytes
 */
void HashEncrypt::hashUpdate(unsigned char *in, int inSizeBytes)
{
    //CXXPROF_ACTIVITY("gcm update");

    EVP_EncryptUpdate(&_ctx, NULL, &_unusedOutl, in, inSizeBytes); //TODO check return value == 1
}


/**
 * Get the final hash of all the updated data
 * @param out destination buffer for the hash value
 * @param outSizeBytes will hold the number of written bytes
 */
void HashEncrypt::hashFinal(unsigned char *out, unsigned int *outSizeBytes)
{
    //CXXPROF_ACTIVITY("gcm final");

    EVP_EncryptFinal_ex(&_ctx, NULL, &_unusedOutl); //TODO check return value == 1

    EVP_CIPHER_CTX_ctrl(&_ctx, EVP_CTRL_GCM_GET_TAG, _finalSizeBytes, out);
    *outSizeBytes = _finalSizeBytes;
}