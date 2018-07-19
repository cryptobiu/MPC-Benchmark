#pragma once

#include <libscapi/include/primitives/HashOpenSSL.hpp>
#include <libscapi/include/cryptoInfra/Key.hpp>
#include <libscapi/include/primitives/Kdf.hpp>
#include <libscapi/include/circuits/BooleanCircuits.hpp>


using namespace std;

/**
* This class provides some utilities regarding keys in order to use in the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class KeyUtils
{
public:
	/**
	* Hashes the given key, then convert the result to a new key.
	* @param key The key to hash.
	* @param hash The hash function to use.
	* @param kdf The kdf object to use in order to convert the hash result into a new key.
	* @param keyLength The required length of the new key.
	* @return The new key.
	*/ 
	static SecretKey hashKey(SecretKey* key, CryptographicHash* hash, KeyDerivationFunction* kdf, int keyLength);

	/**
	* XOR the two given key and return the resulted key.
	* @param k1
	* @param k2
	* @throws InvalidInputException if the lengths of the given keys are different.
	*/
	static SecretKey xorKeys(SecretKey* k1, SecretKey* k2);

	/**
	* Checks if the given keys are equal.
	* @param k1
	* @param k2
	* @return true in case the keys are equal; false, otherwise.
	*/
	static bool compareKeys(SecretKey* k1, SecretKey* k2);
};