#include "../../../include/OfflineOnline/subroutines/OfflineOtReceiverRoutine.hpp"

OfflineOtReceiverRoutine::OfflineOtReceiverRoutine(shared_ptr<ExecutionParameters> execution, shared_ptr<OTBatchReceiver> maliciousOtReceiver, shared_ptr<KProbeResistantMatrix> matrix, shared_ptr<BucketLimitedBundleList> buckets)
{
	//Sets the parameters.
	this->maliciousOtReceiver = maliciousOtReceiver;
	this->matrix = matrix;
	this->buckets = buckets;

	this->numBuckets = execution->getNumberOfExecutions();
	this->bucketSize = execution->getBucketSize();
	this->hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();
	this->keySize = CryptoPrimitives::getAES()->getBlockSize();
	this->m = matrix->getProbeResistantInputSize();
	this->originalLabelsSize = buckets->getLimitedBundle(0, 0)->getInputLabelsY2Size();
}

void OfflineOtReceiverRoutine::run()
{
	//Run OT extension for each bucket.
	for (int bucketId = 0; bucketId < numBuckets; bucketId++) {
		//Generate random boolean input for the original indices.
		auto y1 = CircuitInput::randomInput(originalLabelsSize, CryptoPrimitives::getRandom().get()); // This remains hidden
		//auto y1 = CircuitInput::randomInput(originalLabelsSize, primitives->getRandom().get()); // This remains hidden
		//Transform the random input to extended inputs.
		auto y1Extended = matrix->transformInput(*y1, CryptoPrimitives::getRandom().get());
		//auto y1Extended = matrix->transformInput(*y1, primitives->getRandom().get());

		//Set the originsl inputs to all circuits in this bucket.
		for (int j = 0; j < bucketSize; j++) {
			buckets->getLimitedBundle(bucketId, j)->setY1(y1);
		}
		//Run OT extension on the extended keys.
		runOtExtensionTransfer(y1Extended, bucketId);
		delete y1Extended;
	}
}

void OfflineOtReceiverRoutine::runOtExtensionTransfer(CircuitInput* otInput, int bucketId)
{
	//The sigma input for the OT is the boolean input for the circuit.
	auto sigmaArr = otInput->getInputVectorShared();
	int elementSize = 8 * bucketSize * (keySize + hashSize); // Size of each received "x", in bits.

	//Create the input object using the sigma array and size of each x.
	OTExtensionGeneralRInput input(*sigmaArr, elementSize);
	
	//Execute the OT protocol.
	auto out = maliciousOtReceiver->transfer(&input);
	
	//In case the output is not in the expected type, throw an exception.
	auto outCast = dynamic_pointer_cast<OTOnByteArrayROutput>(out);
	if (outCast == NULL)
	{
		throw CheatAttemptException("unexpected output type");
	}
	auto output = outCast->getXSigma();

	//Get the Y1 extended garbled keys.
	auto receivedKeysY1Extended = breakOtOutputArray(output, bucketId);

	//Set each circuit in this bucket with the received garbled keys.
	for (int j = 0; j < bucketSize; j++) {
		buckets->getLimitedBundle(bucketId, j)->setY1ExtendedInputKeys(make_shared<vector<byte>>(receivedKeysY1Extended[j]));
	}
}

vector<vector<byte>> OfflineOtReceiverRoutine::breakOtOutputArray(vector<byte>& output, int bucketId)
{

	auto hash = CryptoPrimitives::getHash();

	//Will hold the garbled input of each input wire.
	vector<vector<byte>> receivedKeys(bucketSize, vector<byte>(m*keySize));

	int pos = 0;
	shared_ptr<CommitmentBundle> commitments;
	vector<byte> commitment0(hashSize), commitment1(hashSize);
	vector<byte> result(hashSize);
	//For each wire in the transformed input,
	for (int i = 0; i < m; i++)
	{
		//For each circuit in the bucket,
		for (int j = 0; j < bucketSize; j++)
		{
			//Get both commitments of each Y1 extended key of this circuit
			commitments = buckets->getLimitedBundle(bucketId, j)->getCommitmentsY1Extended();
			auto commitmentBytes = commitments->getCommitments();
			
			commitment0.assign(commitmentBytes->begin() + i * 2 * hashSize, commitmentBytes->begin() + (i * 2 + 1) * hashSize);
			commitment1.assign(commitmentBytes->begin() + (i * 2 + 1) * hashSize, commitmentBytes->begin() + (i * 2 + 2) * hashSize);

			//chack that the decommitment is equal to one of the options.
			hash->update(output, pos + keySize, hashSize);
			hash->update(output, pos, keySize);
			hash->hashFinal(result, 0);

			//Checks that c = H(r,x)
			if ((commitment0 != result) && (commitment1 != result)){
				throw CheatAttemptException("decommitment failed! for i = " + to_string(i) + " and j = " + to_string(j));
			}
			
			//Put the created secret key in the receivedKeys map.
			memcpy(&receivedKeys[j][i*keySize], &output[pos], keySize);
			pos += hashSize + keySize;
		}
	}

	return receivedKeys;
}
