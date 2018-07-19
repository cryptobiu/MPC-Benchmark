#include "../../include/common/KeyUtils.hpp"

SecretKey KeyUtils::hashKey(SecretKey * key, CryptographicHash * hash, KeyDerivationFunction * kdf, int keyLength)
{
	//Create vector byte to hold the hash result.
	vector<byte> encodedKey(hash->getHashedMsgSize());
	//Hash the given key.
	hash->update(key->getEncoded(), 0, key->getEncoded().size());
	hash->hashFinal(encodedKey, 0);

	//Convert the hash result into a new key and return it.
	return kdf->deriveKey(encodedKey,0,encodedKey.size(),keyLength);
}

SecretKey KeyUtils::xorKeys(SecretKey * k1, SecretKey * k2)
{
	//Get the encoded keys.
	vector<byte> k1Encoded = k1->getEncoded();
	vector<byte> k2Encoded = k2->getEncoded();
	vector<byte> resultEncoded (k1Encoded.size());

	//Check that the lengths of the keys are equal.
	if (k1Encoded.size() != k2Encoded.size()) {
		throw InvalidInputException("KeyUtils::xorKeys: Keys size not compatible");
	}

	size_t size = k1Encoded.size();
	//Xor each byte.
	for (size_t i = 0; i < size; i++) {
		resultEncoded[i] = (byte)(k1Encoded[i] ^ k2Encoded[i]);
	}

	//Convert the result to SecretKey and return it.
	return SecretKey(resultEncoded, "");
}

bool KeyUtils::compareKeys(SecretKey * k1, SecretKey * k2)
{
	//Compare the encoded keys.
	return k1->getEncoded() == k2->getEncoded();
}
