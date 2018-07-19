#include "../../../include/OfflineOnline/subroutines/OfflineOtSenderRoutine.hpp"

vector<byte> OfflineOtSenderRoutine::buildInput(int bucketId, int b)
{
	//check binary
	assert((0 <= b) && (b <= 1));

	//Allocate space for the input array.
	vector<byte> inputArr (this->m * this->bucketSize * (this->keySize + this->hashSize));
	int pos = 0;

	// For each wire the keys and decommitments for all circuits are grouped together.
	for (size_t i = 0; i < m; i++) {
		for (int j = 0; j < bucketSize; j++) {
			shared_ptr<Bundle> bundle = buckets->getBundle(bucketId, j);

			//Get the xor of the key and commitment mask.
			block tempKey;
			memcpy(&tempKey, bundle->getCommitmentMask()->data(), SIZE_OF_BLOCK);
			block xorKeyWithCmtMask = _mm_xor_si128(bundle->getProbeResistantWire(i,b), tempKey);

			//Get the random value of the decommitment for this wire.
			auto randoms = bundle->getCommitmentsY1Extended()->getDecommitmentsRandoms();
			
			//Put in the input array the key and random. The receiver will use them to verify the commitments of Y1 extended keys.
			memcpy(&inputArr[pos], &xorKeyWithCmtMask, this->keySize);
			pos += this->keySize;
			memcpy(&inputArr[pos], &randoms->at((i * 2 + b) * hashSize), this->hashSize);
			pos += this->hashSize;
			
		}
	}


	return inputArr;
}

void OfflineOtSenderRoutine::runOtExtensionTransfer(int bucketId)
{
	//Get the garbled inputs of each party.
	vector<byte> x0Arr = buildInput(bucketId, 0);
	vector<byte> x1Arr = buildInput(bucketId, 1);

	//Create the input for the OT sender.
	OTExtensionGeneralSInput input(x0Arr, x1Arr, m);

	//Execute the OT protocol.
	this->maliciousOtSender->transfer(&input);
}

OfflineOtSenderRoutine::OfflineOtSenderRoutine(const shared_ptr<ExecutionParameters>& execution, const shared_ptr<KProbeResistantMatrix> & matrix,
	const shared_ptr<BucketBundleList> & buckets, const shared_ptr<OTBatchSender> & maliciousOtSender)
{
	//Sets the parameters.
	this->maliciousOtSender = maliciousOtSender;
	this->buckets = buckets;
	this->numBuckets = execution->getNumberOfExecutions();
	this->bucketSize = execution->getBucketSize();
	this->hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();
	this->keySize = CryptoPrimitives::getAES()->getBlockSize();
	this->m = matrix->getProbeResistantInputSize();
}

void OfflineOtSenderRoutine::run()
{
	for (int bucketId = 0; bucketId < numBuckets; bucketId++) {
		runOtExtensionTransfer(bucketId);
	}
}
