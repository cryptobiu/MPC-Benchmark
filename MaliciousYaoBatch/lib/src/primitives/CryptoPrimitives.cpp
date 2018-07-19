#include "../../include/primitives/CryptoPrimitives.hpp"

shared_ptr<PrgFromOpenSSLAES> CryptoPrimitives::random = nullptr;

shared_ptr<OpenSSLDlogECF2m> CryptoPrimitives::dlog = nullptr;

vector<shared_ptr<CryptographicHash>> CryptoPrimitives::hash = vector<shared_ptr<CryptographicHash>>(1);

shared_ptr<HKDF> CryptoPrimitives::kdf = nullptr;

shared_ptr<OpenSSLAES> CryptoPrimitives::aes = nullptr;

shared_ptr<PrgFromOpenSSLAES> CryptoPrimitives::prg = nullptr;

int CryptoPrimitives::numOfThreads = 0;

void CryptoPrimitives::setCryptoPrimitives(string dlogfile)
{
	random = make_shared<PrgFromOpenSSLAES>();
	auto randomKey = random->generateKey(128);
	random->setKey(randomKey);

	dlog = make_shared<OpenSSLDlogECF2m>(dlogfile, string("K-233"));
	hash[0] = make_shared<OpenSSLSHA256>();
	prg = make_shared<PrgFromOpenSSLAES>();
	byte keyVal[] = { (byte)-13, (byte)29, (byte)-20, (byte)98, (byte)-96, (byte)-51, (byte)-86, (byte)-82, (byte)9, (byte)49, (byte)-26, (byte)92, (byte)-22, (byte)50, (byte)-100, (byte)36 };
	SecretKey key(keyVal, 16, "");
	prg->setKey(key);
	aes = make_shared<OpenSSLAES>();
	kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>());
}

void CryptoPrimitives::setNumOfThreads(int numThreads) {
	CryptoPrimitives::numOfThreads = numThreads;

	if (numOfThreads > 0) {
		hash.resize(numOfThreads);
		for (int i = 0; i < numOfThreads; i++) {
			hash[i] = make_shared<OpenSSLSHA256>();
		}
	}
	else {
		hash.resize(1);
		hash[0] = make_shared<OpenSSLSHA256>();
	}
}

shared_ptr<PrgFromOpenSSLAES> CryptoPrimitives::getRandom() { return CryptoPrimitives::random; }
shared_ptr<PrgFromOpenSSLAES> CryptoPrimitives::getPrg() { return CryptoPrimitives::prg; }
shared_ptr<OpenSSLDlogECF2m> CryptoPrimitives::getDlog() { return CryptoPrimitives::dlog; }
shared_ptr<CryptographicHash> CryptoPrimitives::getHash() { return CryptoPrimitives::hash[0]; }
shared_ptr<CryptographicHash> CryptoPrimitives::getHashForThreads(int index) { return CryptoPrimitives::hash[index]; }
shared_ptr<HKDF> CryptoPrimitives::getHKDF() { return CryptoPrimitives::kdf; }
shared_ptr<AES> CryptoPrimitives::getAES() { return CryptoPrimitives::aes; }
const int CryptoPrimitives::getStatisticalParameter() { return CryptoPrimitives::statisticalParameter; }
const int CryptoPrimitives::getNumOfThreads() { return CryptoPrimitives::numOfThreads; }