
#ifndef INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHABSTRACT_HPP
#define INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHABSTRACT_HPP

#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <libscapi/include/infra/Common.hpp>


using namespace std;

/**
 * Abstract class for defining the interface of hasing: init, update and final
 */
class HashAbstract
{
public:
    virtual void hashUpdate(unsigned char *in, int inSizeBytes) = 0;
    // hashFinal implementation should set initialized to false
    virtual void hashFinal(unsigned char *out, unsigned int *outSizeBytes) = 0;
//    virtual void hashReset() = 0;

    void getHashedDataOnce(unsigned char *in, int inSizeBytes, unsigned char *out,
                           unsigned int *outSizeBytes)
    {
        hashUpdate(in, inSizeBytes);
        hashFinal(out, outSizeBytes);
    }

};


#endif //INC_20160901_MALICIOUSMPC_DOUBLEBUFFER_HASHABSTRACT_HPP