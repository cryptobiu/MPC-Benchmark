#include <openssl/evp.h>

#include "AES_PRG.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

//
// WE USE THE AES_ECB method and not AES_CTR as AES_CTR is not avaialble by default
// in some commonly used Linux versions (including Centos7 servers)
//
// We therfroe use a fixed IV passed to the openssl INIT function
//
unsigned char PRG::m_defaultiv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};


//
// DEFAULT Ctor uses the default IV and cache size. Cache size default is set to 88
// as this is a devisor of both 44 (used for 44 bytes) and 8 for AES pipelining
// this means we compute 88*128 bits and cache them
PRG::PRG() : PRG(nullptr,(byte*)m_defaultiv,DEFAULT_CACHE_SIZE) { }

//
// Construction of the PRG. This is a private method called from the singleton instance
// method
//
PRG::PRG(byte *key, byte *iv,int cacheSize)
{

   //key is always null, as we want to seed it from a random source
   if (key == nullptr)
   {
      //we seed from dev/random  in blocking mode to get 16 bytes
      key = new byte[16]();
      int randomData = open("/dev/urandom", O_RDONLY);
      char *myRandomData = (char *)key;
      size_t randomDataLen = 0;
      while (randomDataLen < 16)
      {
          ssize_t result = read(randomData, myRandomData + randomDataLen, 16 - randomDataLen);
          if (result < 0)
          {
             // error, unable to read /dev/random
           }
           randomDataLen += result;
       }
       close(randomData);

   }

   //Initialization of buffer counters and dome additional data structures
    m_key = key;
    m_iv = iv;
    m_idx = 0;
    m_cacheSize = cacheSize;
    m_cachedRandomsIdx = m_cacheSize;

    //INIT openssl. also creates the key schedule data structures internally
    EVP_CIPHER_CTX_init(&m_enc);
    EVP_EncryptInit(&m_enc, EVP_aes_128_ecb(),m_key, m_iv);

    m_cachedRandoms = new byte[m_cacheSize*16]();
    m_ctr = new byte[m_cacheSize*16]();

 //   cout << "CACHE SIZE = " << m_cacheSize << '\n';

    //This method created the first buffer of  CACHHE_SIZE*128Bit
    prepare(1);

}

//
// DTOR CLEANUP. ONLY CALLED IN END OF PROGRAM SINCE THIS IS A SINGLETON
//
PRG::~PRG()
{
    delete m_cachedRandoms;
    EVP_CIPHER_CTX_cleanup(&m_enc);
}

// INTERNAL METHOD USED TO GET THE NEXT 128bit pointer. Recreates cache if necessary
byte * PRG::getRandomBytes()
{
    if(m_cachedRandomsIdx==m_cacheSize)
    {
        //cout << "PREPARE" << '\n';
        prepare(0);
    }
    byte *ret = m_cachedRandoms + m_cachedRandomsIdx*16;
    m_cachedRandomsIdx++;

    return ret;

}

//
// CREATES A NEW BUFFER OF CACHE SIZE * 128 bit
//
void PRG::prepare(int isPlanned)
{

    int actual;

	unsigned long *p = (unsigned long *)m_ctr;
    // update and write the counter. we use a long counter so in every 128bit counter buffer,
    // 64 low bits will be 0 and 64 high bits will include the counter

    for (int i = 0; i < m_cacheSize; i++)
    {
       p++;
       m_ctr_count = m_ctr_count+1;
       (*p) = m_ctr_count;
	   p++;

    }

    //perform the encrytpion
    EVP_EncryptUpdate(&m_enc, m_cachedRandoms, &actual , m_ctr, 16*m_cacheSize );

    //reset pointers
    m_cachedRandomsIdx = 0;
    m_idx = 0;
}


//
// THIS METHOD RETURNS A 32 BIT NUMBER. IT  USES the latest 128bit,
// 4 consecutive calls will return [0:31],[32:63],[64:95],[96:127]
//
//
uint32_t PRG::getRandom()
{
    switch (m_idx)
    {
        case 0:
        {

            m_pIdx = (uint32_t*) getRandomBytes();
            m_u1 = *m_pIdx;
            m_pIdx++;
            m_idx++;
            return m_u1;
        }

        case 1:
        {
            m_u2 = *m_pIdx;
            m_pIdx++;
            m_idx++;
	    return m_u2;
        }

        case 2:
        {
            m_u3 = *m_pIdx;
            m_pIdx++;
            m_idx++;
            return m_u3;
        }

        case 3:
        {
            m_u4 = *m_pIdx;
            m_idx = 0;
            return m_u4;
        }
    }
}


//
// WE CANNOT CHECK AESNI ENABLED WITHOUT STATIC LINK, SO WE DO A NULL TEST
//
void PRG::checkAESNI()
{

}

const char* UnsupportAESNIException::what() const throw()
{
    return "AESNI not supported at this computer\n program terminated";
}


//
// SINGLETON METHOD
//
PRG& PRG::instance()
{
    if (_prg == 0)
	_prg = new PRG();

    return (*_prg);
}


PRG* PRG::_prg = 0;
