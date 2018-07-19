#include "../../../include/OfflineOnline/primitives/BundleBuilder.hpp"

shared_ptr<vector<byte>> BundleBuilder::generatePlacementMask(byte* inputWiresX)
{
	vector<byte> placementMask(numberOfInputLabelsP1);
	for (int i = 0; i < numberOfInputLabelsP1; i++)
	{
		placementMask[i] = (byte)(inputWiresX[(2 * i + 1)*keySize - 1] & 1);
	}

	return make_shared<vector<byte>>(placementMask);
}

void BundleBuilder::initRandomness(vector<byte> * seed)
{
	auto randomProvider = SeededRandomnessProvider(seed);
	
	//Generate keys and random sources.
	this->mesP2InputKeys =  make_shared<OpenSSLAES>(randomProvider.getP2InputKeysSecureRandom());
	this->randomSourceMasks = randomProvider.getMasksSecureRandom();
	this->randomSourceCommitments = randomProvider.getCommitmentsSecureRandom();
	this->randomGarble = randomProvider.getGarblingSecureRandom();
	this->keySize = this->mesP2InputKeys->getBlockSize();
}

tuple<block*, block*, std::vector<byte>> BundleBuilder::garble()
{
	vector<byte> seed(SIZE_OF_BLOCK);
	randomGarble->getPRGBytes(seed, 0, SIZE_OF_BLOCK);

	block seedB;
	memcpy(&seedB, seed.data(), SIZE_OF_BLOCK);

	// garble the circuit.
	//tuple<block*, block*, std::vector<byte> >
	auto values = this->gbc->garble((block*)&seedB);

	inputWiresX.resize(numberOfInputLabelsP1 * 2);
	inputWiresY1.resize(numberOfInputLabelsP2 * 2);
	inputWiresY2.resize(numberOfInputLabelsP2 * 2);

	//Fill inputWiresX and inputWiresY from the output of the garble function.
	inputWiresX.assign(get<0>(values), get<0>(values) +numberOfInputLabelsP1 * 2);
	auto inputWiresY = get<0>(values) + numberOfInputLabelsP1 * 2;
	//inputWiresY = convertByteVectorToBlockVectorAligned(vector<byte>(startWiresY, startWiresY + numberOfInputLabelsP2 * 2 * keySize));
	//Split Y keys into Y1 and Y2 keys.
	splitKeys(inputWiresY);

	//Fill inputWiresY1Extended keys using the matrix.
	matrix->transformKeys(inputWiresY1, mesP2InputKeys.get(), inputWiresY1Extended);

	return values;
}

void BundleBuilder::splitKeys(block * inputWiresY)
{
	block yDelta;
	block* y0;
	block* y1;

	//1. Get both keys of each wire (y0, y1)
	//2. Choose a random key w0
	//3. Compute z0 = y0 ^ w0
	//			 w1 = w0 ^ delta
	//			 z1 = z0 ^ delta
	//4. set (k0, k1) to be one set of keys to Y0 and (z0,z1) to bw set of keys to Y2.
	for (int i = 0; i < numberOfInputLabelsP2; i++)
	{
		//get Y0, y1.		
		y0 = &inputWiresY[i * 2];
		y1 = &inputWiresY[i * 2 + 1];

		//In case this is the first time, get delta = y0^y1.
		if (i == 0)
		{
			yDelta = _mm_xor_si128(*y0, *y1);
			
		}

		//w0
		auto w0 = mesP2InputKeys->generateKey(KEY_SIZE).getEncoded();
		memcpy(&inputWiresY1[i * 2], &w0[0], keySize);
		// w0 ^ z0 complete to y0.
		//w1
		inputWiresY1[i * 2 + 1] = _mm_xor_si128(inputWiresY1[i * 2], yDelta);
		//z0
		inputWiresY2[i * 2] = _mm_xor_si128(*y0, inputWiresY1[i * 2]);
		//z1
		inputWiresY2[i * 2 + 1] = _mm_xor_si128(inputWiresY2[i * 2], yDelta);
	}
}

BundleBuilder::BundleBuilder(const shared_ptr<GarbledBooleanCircuit> & gbc, const shared_ptr<KProbeResistantMatrix> & matrix)
{
	this->gbc = gbc;
	this->matrix = matrix;
	this->random = CryptoPrimitives::getRandom();

	// Fixed labels.
	numberOfProbeResistantLabels = matrix->getProbeResistantInputSize();
}

shared_ptr<Bundle> BundleBuilder::build(int seedSizeInBytes, shared_ptr<CryptographicHash> & hash)
{
	//create seeded vector byte
	auto vec = make_shared<vector<byte>>(seedSizeInBytes);
	random->getPRGBytes(*vec, 0, seedSizeInBytes);

	return build(vec, hash);
}

shared_ptr<Bundle> BundleBuilder::build(const shared_ptr<vector<byte>> & seed, const shared_ptr<CryptographicHash> & hash)
{
	//Initialize the random sources with the given seed.
	//TODO - fix - do not use constants.
	initRandomness(seed.get());
	
	//Get the input and output wire's indices.
	numberOfInputLabelsP1 = gbc->getNumOfInputsForEachParty()[0];
	numberOfInputLabelsP2 = gbc->getNumOfInputsForEachParty()[1];
	numberOfOutputLabels = gbc->getNumberOfOutputs();	
	
	inputWiresY1Extended.clear();
	//Garble the circuit.
	auto wireValues = garble();

	// Creates m, the size of m is the same as x.
	auto commitmentMask = make_shared<vector<byte>>(keySize);
	shared_ptr<vector<byte>> placementMask = generatePlacementMask((byte*)inputWiresX.data());
	makeRandomBitByteVector(randomSourceMasks.get(), *commitmentMask);
	
	//Commit on the keys.
	auto committer = make_shared<CmtSimpleHashCommitter>(nullptr, randomSourceCommitments, hash, CryptoPrimitives::getHash()->getHashedMsgSize());
	auto commitmentsX = make_shared <CommitmentBundle>(randomSourceCommitments.get(), hash.get(), keySize, inputWiresX, numberOfInputLabelsP1, *commitmentMask, *placementMask);
	auto commitmentsY2 = make_shared <CommitmentBundle>(randomSourceCommitments.get(), hash.get(), keySize, inputWiresY2, numberOfInputLabelsP2, *commitmentMask);
	auto commitmentsY1Extended = make_shared <CommitmentBundle>(randomSourceCommitments.get(), hash.get(), keySize, inputWiresY1Extended, numberOfProbeResistantLabels, *commitmentMask);
	
	//The commitments on the output keys can be done once and not for each wire separately.
	int numberOfBytesOutput = keySize * 2 * numberOfOutputLabels;
	byte* start = (byte*)get<1>(wireValues);
	vector<byte> tmp(start, start + numberOfBytesOutput);

	//Create hash committer object.
	shared_ptr<CmtCommitValue> commitValue = committer->generateCommitValue(tmp);

	//Commit and decommit on the keys. The commitment and decommitment objects are saved as class members.
	shared_ptr<CmtCCommitmentMsg> commitment = committer->generateCommitmentMsg(commitValue, 0);
	shared_ptr<CmtCDecommitmentMessage> decommit = committer->generateDecommitmentMsg(0);
	
	//Create and return a new Bundle with the built data.
	return make_shared<Bundle>(seed, this->gbc, get<1>(wireValues), numberOfOutputLabels, placementMask, commitmentMask, numberOfInputLabelsP1, 
		numberOfInputLabelsP2, inputWiresY1Extended, commitmentsX, commitmentsY1Extended, 
		commitmentsY2, commitment, decommit, secret, keySize);
}

