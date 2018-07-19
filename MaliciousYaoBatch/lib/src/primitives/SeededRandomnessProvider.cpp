#include "../../include/primitives/SeededRandomnessProvider.hpp"

shared_ptr<PrgFromOpenSSLAES> SeededRandomnessProvider::getSeededSecureRandom(vector<byte>& seed)
{
	auto prg = make_shared<PrgFromOpenSSLAES>();
	SecretKey sk(seed, "");
	prg->setKey(sk);
	return prg;
}

SeededRandomnessProvider::SeededRandomnessProvider(vector<byte>* seed)
{
	SecretKey sk(*seed, "");
	random.setKey(sk);

	//create 4 const seed
	random.getPRGBytes(garbledCircuitSeed, 0, SIZE_OF_BLOCK);
	random.getPRGBytes(p2InputKeysSeed, 0, SIZE_OF_BLOCK);
	random.getPRGBytes(masksSeed, 0, SIZE_OF_BLOCK);
	random.getPRGBytes(commitmentsSeed, 0, SIZE_OF_BLOCK);
}

shared_ptr<PrgFromOpenSSLAES> SeededRandomnessProvider::getGarblingSecureRandom()
{
	return getSeededSecureRandom(garbledCircuitSeed);
}

shared_ptr<PrgFromOpenSSLAES> SeededRandomnessProvider::getP2InputKeysSecureRandom()
{
	return getSeededSecureRandom(p2InputKeysSeed);
}

shared_ptr<PrgFromOpenSSLAES> SeededRandomnessProvider::getMasksSecureRandom()
{
	return getSeededSecureRandom(masksSeed);
}

shared_ptr<PrgFromOpenSSLAES> SeededRandomnessProvider::getCommitmentsSecureRandom()
{
	return getSeededSecureRandom(commitmentsSeed);
}