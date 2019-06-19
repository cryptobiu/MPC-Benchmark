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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if(EVP_CIPHER_CTX_init(&_ctx) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_EncryptInit_ex(&_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_CIPHER_CTX_ctrl(&_ctx, EVP_CTRL_GCM_SET_IVLEN, ivSizeBytes, NULL) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_EncryptInit_ex(&_ctx, NULL, NULL, _key, _iv) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#else
    if(EVP_CIPHER_CTX_init(_ctx) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_EncryptInit_ex(_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, ivSizeBytes, NULL) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if (EVP_EncryptInit_ex(_ctx, NULL, NULL, _key, _iv) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#endif

}

/**
 * DTOR
 */
HashEncrypt::~HashEncrypt()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(&_ctx);
#else
    EVP_CIPHER_CTX_cleanup(_ctx);
#endif

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_EncryptUpdate(&_ctx, NULL, &_unusedOutl, in, inSizeBytes) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#else
    if (EVP_EncryptUpdate(_ctx, NULL, &_unusedOutl, in, inSizeBytes) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#endif
}


/**
 * Get the final hash of all the updated data
 * @param out destination buffer for the hash value
 * @param outSizeBytes will hold the number of written bytes
 */
void HashEncrypt::hashFinal(unsigned char *out, unsigned int *outSizeBytes)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_EncryptFinal_ex(&_ctx, NULL, &_unusedOutl) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if(EVP_CIPHER_CTX_ctrl(&_ctx, EVP_CTRL_GCM_GET_TAG, _finalSizeBytes, out) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#else
    if (EVP_EncryptFinal_ex(_ctx, NULL, &_unusedOutl) == 0)
        throw IllegalStateException("Cannot create Hash Object");

    if(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, _finalSizeBytes, out) == 0)
        throw IllegalStateException("Cannot create Hash Object");
#endif
    *outSizeBytes = _finalSizeBytes;
}