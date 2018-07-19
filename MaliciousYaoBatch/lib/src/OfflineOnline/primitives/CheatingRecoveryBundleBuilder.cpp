#include "../../../include/OfflineOnline/primitives/CheatingRecoveryBundleBuilder.hpp"

void CheatingRecoveryBundleBuilder::generateYKeys(block& masterKey, const shared_ptr<vector<byte>> & sigmaArray, block & delta, vec_block_align& inputWiresY)
{
	int lastIndex = numberOfInputLabelsP2 - 1;

	block xorOfShares;
	block currentKey;

	//Generate both keys for each p2 wire.
	for (int i = 0; i < lastIndex; i++)
	{
		//Generate two random keys.
		auto key0Byte = mesP2InputKeys->generateKey(KEY_SIZE).getEncoded();
		//copy from vector<byte> to vec_block_align
		memcpy(&inputWiresY[i * 2], &key0Byte[0], keySize);

		inputWiresY[i * 2 + 1] = _mm_xor_si128(inputWiresY[i * 2], delta);
		
		//Get the key that matches the sigma of this wire.
		if (sigmaArray->at(i) == 1)
		{
			currentKey = inputWiresY[i * 2 + 1];
		}
		else
		{
			currentKey = inputWiresY[i * 2];
		}
		if (i == 0)
		{
			// The xor of just the first key is the first key.
			xorOfShares = currentKey;
		}
		else
		{
			// The xor of the current key with the previous xor is the xor of all keys.
			xorOfShares = _mm_xor_si128(xorOfShares, currentKey);
		}
	}
	/*auto lastSharePair0 = inputWiresY[lastIndex * 2];
	auto lastSharePair1 = inputWiresY[lastIndex * 2 + 1];

	//The last pair of keys is the Xor of all sigma keys with the master key and a random key.
	switch (sigmaArray->at(lastIndex))
	{
	case 0:
	lastSharePair0 = _mm_xor_si128(xorOfShares, masterKey);
	lastSharePair1 = _mm_xor_si128(lastSharePair0, delta);
	break;
	case 1:
	lastSharePair1 = _mm_xor_si128(xorOfShares, masterKey);
	lastSharePair0 = _mm_xor_si128(lastSharePair1, delta);
	break;
	}*/
	inputWiresY[lastIndex * 2 + sigmaArray->at(lastIndex)] = _mm_xor_si128(xorOfShares, masterKey);
	inputWiresY[lastIndex * 2 + 1 - sigmaArray->at(lastIndex)] = _mm_xor_si128(inputWiresY[lastIndex * 2 + sigmaArray->at(lastIndex)], delta);

}

tuple<block*, block*, std::vector<byte>> CheatingRecoveryBundleBuilder::garble()
{
	vector<byte> seed(SIZE_OF_BLOCK);
	randomGarble->getPRGBytes(seed, 0, SIZE_OF_BLOCK);

	block seedB;
	memcpy(&seedB, seed.data(), SIZE_OF_BLOCK);

	// garble the circuit.
	//tuple<block*, block*, std::vector<byte> >
	auto wireValues = gbc->garble((block*)&seedB);

	//Fill inputWiresX from the output of the garble function.
	inputWiresX.resize(numberOfInputLabelsP1 * 2);
	memcpy(&inputWiresX[0], get<0>(wireValues), 2 * numberOfInputLabelsP1);

	// Override P2 input keys with the secret sharing input keys.
	numberOfInputLabelsP2 = proofOfCheating->size();
	vec_block_align inputWiresY(numberOfInputLabelsP2 * 2);
	inputWiresY1.resize(numberOfInputLabelsP2 * 2);
	inputWiresY2.resize(numberOfInputLabelsP2 * 2);

	// Obtain the master key and generate P2 keys according to the master key.
	auto masterKey = get<0>(wireValues)[2 * numberOfInputLabelsP1 + 1];

	//Calculate the delta used in the circuit.
	block delta = _mm_xor_si128(inputWiresX[0], inputWiresX[1]);

	generateYKeys(masterKey, proofOfCheating->getInputVectorShared(), delta, inputWiresY);

	//Split P2 keys into Y1 and Y2 keys.
	splitKeys(inputWiresY.data());

	//Fill inputWiresY1Extended keys using the matrix.
	matrix->transformKeys(inputWiresY1, mesP2InputKeys.get(), inputWiresY1Extended);

	return wireValues;
}

CheatingRecoveryBundleBuilder::CheatingRecoveryBundleBuilder(const shared_ptr<GarbledBooleanCircuit> & gbc, const shared_ptr<KProbeResistantMatrix> & matrix,
	 SecretKey & proofOfCheating) :BundleBuilder(gbc, matrix) {
	this->secret = proofOfCheating;
	this->proofOfCheating = CircuitInput::fromSecretKey(proofOfCheating);
}
