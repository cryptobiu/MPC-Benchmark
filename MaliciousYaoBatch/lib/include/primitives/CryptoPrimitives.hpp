#pragma once

#include <libscapi/include/primitives/DlogOpenSSL.hpp>
#include <libscapi/include/primitives/HashBlake2.hpp>
#include <libscapi/include/primitives/PrfOpenSSL.hpp>
#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/primitives/Kdf.hpp>

using namespace std;


/**
* This class defines some primitives objects to use in the protocol.
*/
class CryptoPrimitives {
private:
	static shared_ptr<PrgFromOpenSSLAES> random;

	static shared_ptr<OpenSSLDlogECF2m> dlog;

	static vector<shared_ptr<CryptographicHash>> hash;

	static shared_ptr<HKDF> kdf;

	static shared_ptr<PrgFromOpenSSLAES> prg;

	static shared_ptr<OpenSSLAES> aes;

	static int const statisticalParameter = 40;

	static int numOfThreads;

public:
	static void setCryptoPrimitives(string dlogfile);
	static void setNumOfThreads(int numThreads);

	//get primitives
	static shared_ptr<PrgFromOpenSSLAES> getRandom();
	static shared_ptr<OpenSSLDlogECF2m> getDlog();
	static shared_ptr<CryptographicHash> getHash();
	static shared_ptr<CryptographicHash> getHashForThreads(int index);
	static shared_ptr<HKDF> getHKDF();
	static shared_ptr<PrgFromOpenSSLAES> getPrg();
	static shared_ptr<AES> getAES();
	static const int getStatisticalParameter();
	static const int getNumOfThreads();

};