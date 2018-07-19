#include "../../../include/OfflineOnline/specs/OnlineProtocolP2.hpp"

/**
* Computes the main circuits part.
*
* pseudo code:
* 1. Receive the requested input from p2
* 2. Send the commitment masks
* 3. Decommit of p2 input wires' keys
* 4. Send the xor of the placement mask with the input
* 5. Decommit of p1 input wires' keys
* 6. Select and encrypt proof to send to p2
* @throws IOException
*/
void OnlineProtocolP2::evaluateMainCircuit() {
	//	LogTimer timer = new LogTimer("selectAndSendY2");
	auto y2 = selectAndSendY2(mainBucket.get(), input);
	//	timer.stop();

	//	timer.reset("receivePackage");
	EvaluationPackage mainPackage = receivePackage();
	//	timer.stop();

	//	timer.reset("receiveCommitmentMasks");
	receiveCommitmentMasks(mainBucket.get(), mainPackage);
	//	timer.stop();

	//	timer.reset("receiveAndVerifyY2InputKeys");
	receiveAndVerifyY2InputKeys(mainBucket.get(), mainPackage, mainMatrix, y2);

	//	timer.stop();

	//	timer.reset("receivePlacementMasks");
	receivePlacementMasks(mainBucket.get(), mainPackage);
	//	timer.stop();

	//	timer.reset("receiveAndVerifyXInputKeys");
	receiveAndVerifyXInputKeys(mainBucket.get(), mainPackage);
	//	timer.stop();

	//	timer.reset("receiveEncryptedProof");
	receiveEncryptedProof(mainBucket.get(), mainPackage);
	//	timer.stop();

	//	timer.reset("computeEvaluationCircuits");
	computeEvaluationCircuits(mainBucket);
	//timer.stop();
}

void OnlineProtocolP2::evaluateCheatingRecoveryCircuit() {
	//	LogTimer timer = new LogTimer("selectAndSendD2");
	auto crInput = CircuitInput::fromSecretKey(proofOfCheating);
	auto d2 = selectAndSendY2(crBucket.get(), *crInput);
	//	timer.stop();

	//	timer.reset("receivePackage");
	EvaluationPackage crPackage = receivePackage();
	//	timer.stop();

	//	timer.reset("receiveCommitmentMasks");
	receiveCommitmentMasks(crBucket.get(), crPackage);
	//	timer.stop();

	//	timer.reset("receiveAndVerifyD2InputKeys");
	receiveAndVerifyD2InputKeys(crBucket.get(), crPackage, crMatrix, d2);
	//	timer.stop();

	//	timer.reset("receivePlacementMasks");
	receivePlacementMasks(crBucket.get(), crPackage);
	//	timer.stop();

	//	timer.reset("receiveAndVerifyXInputKeys");
	receiveAndVerifyXInputKeys(crBucket.get(), crPackage);
	//	timer.stop();

	//	timer.reset("receiveAndVerifyOutputKeys");
	receiveAndVerifyOutputKeys(mainBucket.get(), crPackage);
	//timer.stop();

	//	timer.reset("computeCheatingRecoveryCircuit");
	computeCheatingRecoveryCircuit(crBucket);
	//	timer.stop();
}

/**
* Receives the package from p1. This package contain all the necessary messages during the protocol.
* This gives better performance than sending each message separately.
* @return The received message.
* @throws CheatAttemptException In case the received message is not an EvaluationPackage instance.
* @throws IOException If there as a problem during the communication.
*/
EvaluationPackage OnlineProtocolP2::receivePackage() {
	EvaluationPackage package;
	//vector<byte> msg;
	//channel->readWithSizeIntoVector(msg);
	//package.initFromByteVector(msg);
	readSerialize(package, channel.get());
	return package;
}

/**
* Computes the xor of the given input and the y1 keys that were generated in the offline protocol.
* Sends the result to the other party and returns it.
* @param bucket The bucket to work on.
* @param y The input for the circuit.
* @return The result of the xor of the given input and the y1 keys
* @throws IOException If there as a problem during the communication.
*/
vector<byte> OnlineProtocolP2::selectAndSendY2(BucketLimitedBundle* bucket, CircuitInput & y) {

	//Xor the given input and the y1 keys that were generated in the offline protocol.
	auto y2 = CircuitInput::xorCircuits(&y, bucket->getLimitedBundleAt(0)->getY1().get());
	
	//Send the result to p1.
	channel->writeWithSize(y2.data(), y2.size());

	//Return the reault.
	return y2;
}

/**
* Extract the commitment mask of each circuit in the bucket from the received evaluationPackage and put it in the circuit.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
*/
void OnlineProtocolP2::receiveCommitmentMasks(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage) {
	int size = CryptoPrimitives::getAES()->getBlockSize();

	//For each circuit in the bucket, extract the commitment mask and set it in the circuit.
	auto bucketSize = bucket->size();
	for (size_t j = 0; j < bucketSize; j++) {

		vector<byte> commitmentMask(size);
		memcpy(commitmentMask.data(), evaluationPackage.getCommitmentMask().data() + j*size, size);
		bucket->getLimitedBundleAt(j)->setCommitmentMask(commitmentMask);
	}
}

/**
* Checks that the given random values and committed values are indeed lead to the commitments values.
* @param comm The commitments values.
* @param r The random values used to commit.
* @param x The values to commit on.
* @return true if the commitments match the values and randoms; false, otherwise.
*/
bool OnlineProtocolP2::verifyDecommitment(CryptographicHash* hash, vector<byte> & comm, vector<byte> & r, vector<byte> & x) {

	size_t rounds = x.size() / SIZE_OF_BLOCK;
	size_t hashSize = r.size() / rounds;

	vector<byte> output;

	for (size_t j = 0; j<rounds; j++) {
		
		hash->update(r, j*hashSize, hashSize);
		hash->update(x, j*SIZE_OF_BLOCK, SIZE_OF_BLOCK);
		hash->hashFinal(output, 0);

		//bool equal = true;
		for (size_t i = 0; i<hashSize; i++) {
			if (output[i] != (comm.data() + j*hashSize)[i]) {
				cout << "not equal. j = " << j << endl;
				return false;
			}
		}
	}

	return true;
}

/**
* Gets the keys and mask and xor each key with the mask.
* The result is placed in the keys array.
* @param keys The keys to xor with the mask. This content is changed during the method and the output is places here.
* @param mask The mask to use in order to xor each key.
* @param size The number of keys.
*/
void OnlineProtocolP2::xorKeysWithMask(block* keys, int size, vector<byte> & maskArray) {
	block mask;
	memcpy(&mask, maskArray.data(), sizeof(block));

	for (size_t i = 0; i < size; i++) {
		keys[i] = _mm_xor_si128(keys[i], mask);
	}
}

/**
* Verifies that the received decommitments on the input keys are correct.
* In case they are, extract the keys and sets them in the circuits.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
* @param matrix The probe resistant matrix to use in order to restore the original keys from the extended keys.
* @param y2 The boolean input for the circuit.
* @param from The starting index in the bucket that point on the first circuit to work on.
* @param to The last index in the bucket that point on the last circuit to work on.
*/
void OnlineProtocolP2::verifyY2InputKeys(BucketLimitedBundle* bucket, EvaluationPackage * evaluationPackage,
	KProbeResistantMatrix * matrix, vector<byte> * y2, int from, int to, int threadIndex) {
	//The labels are equal in all circuits.
	auto numberOfInputsY2 = bucket->getLimitedBundleAt(0)->getInputLabelsY2Size();

	int keyLength = CryptoPrimitives::getAES()->getBlockSize();
	int hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();

	//For each circuit in the given range, verify the decommitment on the input keys.
	for (int k = from; k<to; k++) {
		//Get the circuit, commitment mask and commitments on the keys.
		auto circuitBundle = bucket->getLimitedBundleAt(k);
		auto commitmentMask = circuitBundle->getCommitmentMask();
		auto commitmentBundleY2 = circuitBundle->getCommitmentsY2();

		//Get the extended keys generated in the offline phase.
		auto inputKeysY1Extended = circuitBundle->getY1ExtendedInputKeys();
		auto cloneY1Extended = convertByteVectorToBlockArray(inputKeysY1Extended.get());
		int size = inputKeysY1Extended->size() / SIZE_OF_BLOCK;
		// Call the native method that xor the commitment mask with Y1 extended keys received in offline phase.
		xorKeysWithMask(cloneY1Extended, size, commitmentMask);
		int n = 0;
		//Restore the original y1 keys using the given probe resistant matrix and the result of xoring the commitment mask with Y1 extended keys.
		auto y1Keys = matrix->restoreKeys(cloneY1Extended, size, n);

		//Copy the commitments, values and random values to a one dimension array in order to get better performance in the native implementation.
		vector<byte> commitments(numberOfInputsY2 * hashSize);
		vector<byte> randoms(numberOfInputsY2 * hashSize);
		vector<byte> values(numberOfInputsY2 * keyLength);
		
		auto decommitmentRandoms = evaluationPackage->getRandomDecommitmentY2InputKey();
		auto decommitmentX = evaluationPackage->getXDecommitmentY2InputKey();
		
		for (size_t i = 0; i < numberOfInputsY2; i++) {
			
			auto com = commitmentBundleY2->getCommitments();

			memcpy(commitments.data() + i*hashSize, com->data() + i * 2 * hashSize + y2->at(i) * hashSize, hashSize);
			memcpy(randoms.data() + i*hashSize, decommitmentRandoms.data() + hashSize * (k*numberOfInputsY2 + i) , hashSize);
			memcpy(values.data() + i*keyLength, decommitmentX.data() + keyLength*(k*numberOfInputsY2 + i), keyLength);
		}

		//Checks that the random values and committed values are indeed lead to the commitments values.
		bool valid = verifyDecommitment(CryptoPrimitives::getHashForThreads(threadIndex).get(), commitments, randoms, values);

		//If the verify failed, there is a cheating. Throw an exception.
		if (valid == false) {
			throw CheatAttemptException("incorrect decommitment!");
		}

		//Xor the keys with the commitment mask to get the y2 keys.
		auto valuesBlocks = convertByteVectorToBlockArray(&values);
		int valuesSize = values.size() / SIZE_OF_BLOCK;
		xorKeysWithMask(valuesBlocks, valuesSize, commitmentMask);

		//Xor y1 keys and y2 keys to get y keys.
		auto yKeys = BinaryUtils::xorBlockArray(valuesBlocks, valuesSize, y1Keys, n);

		//Set y keys to the circuit.
		vector<byte> yKeysVec = convertBlockArrayToByteVector(yKeys, n);
		circuitBundle->setYInputKeys(yKeysVec);
		_mm_free(yKeys);
		_mm_free(valuesBlocks);
        _mm_free(cloneY1Extended);
		_mm_free(y1Keys);
	}
}

/**
* Verifies that the received decommitments on the input keys are correct.
* In case they are, extract the keys and sets them in the circuits.
* In case the user enable threads, this function is split into the number of threads as the user requested.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
* @param matrix The probe resistant matrix to use in order to restore the original keys from the extended keys.
* @param y2 The boolean input for the circuit.
*/
void OnlineProtocolP2::receiveAndVerifyY2InputKeys(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage, KProbeResistantMatrix * matrix, vector<byte> & y2) {
	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < bucket->size()) ? CryptoPrimitives::getNumOfThreads() : bucket->size();
	
		vector<thread> threads;

        //Calculate the number of circuit in each thread and the remainder.
        int numOfCircuits = (bucket->size() + threadCount - 1)/ threadCount;
        int remain  = bucket->size();

        //Create the threads and assign to each one the appropriate circuits.
		for (int j = 0; j < threadCount; j++) {
			if (remain >= numOfCircuits){
				threads.push_back(thread(&OnlineProtocolP2::verifyY2InputKeys, this,
					bucket, &evaluationPackage, matrix, &y2, j*numOfCircuits, (j + 1)*numOfCircuits, j));
                remain -= numOfCircuits;

			} else if (remain > 0){
				threads.push_back(thread(&OnlineProtocolP2::verifyY2InputKeys, this, bucket,
					&evaluationPackage, matrix, &y2, j*numOfCircuits, bucket->size(), j));
                remain = 0;
			}
		}

		//Wait until all threads finish their job.
		for (int j = 0; j < threads.size(); j++) {
            threads[j].join();
            threads[j].~thread();
		}
	//In case no thread should be created, verify all the circuits input directly.
	} else {
		verifyY2InputKeys(bucket, &evaluationPackage, matrix, &y2, 0, bucket->size(), 0);
	}
}

/**
* verifies that the received decommitments on the d2 input keys are correct.
* @param bucket The bucket to work on.
* @param matrix The probe resistant matrix to use in order to restore the original keys from the extended keys.
* @param evaluationPackage The message that was received from p1.
* @param d2 The boolean input for the cheating recovery circuit.
*/
void OnlineProtocolP2::receiveAndVerifyD2InputKeys(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage, KProbeResistantMatrix * matrix, vector<byte> & d2) {
	// Since the real placement of the master key must be fixed when synthesizing the input keys
	// we cannot send the completion to D, but to D' (which is the master proof of cheating).
	// so D ^ D' = M, where M is the mask that we need to apply on d2.

	auto maskOnD2 = evaluationPackage.getMaskOnD2();
	auto size = d2.size();
	//Xor the inputs with the mask.
	vector<byte> modifiedD2(size);
	for (size_t i = 0; i < size; i++) {
		modifiedD2[i] = d2[i] ^ maskOnD2[i];
	}
	//Call the function that verifies with the xor result.
	receiveAndVerifyY2InputKeys(bucket, evaluationPackage, matrix, modifiedD2);
}

/**
* Receive the placement mask and check that the difference is as expected.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
*/
void OnlineProtocolP2::receivePlacementMasks(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage) {

	auto size = input.size();

	//For each circuit in the bucket, check the placement mask.
	auto bucketSize = bucket->size();
	for (size_t j = 0; j < bucketSize - 1; j++) {

		//Get the circuit and its placement mask.
		auto circuitBundle = bucket->getLimitedBundleAt(j);

		vector<byte> currMask(size);
		vector<byte> nextMask(size);
		memcpy(currMask.data(), evaluationPackage.getPlacementMask().data() + j*size, size);

		//Take the nest placement mask.
		memcpy(nextMask.data(), evaluationPackage.getPlacementMask().data() + (j + 1)*size, size);

		//compute the xor of both masks.
		vector<byte> actualDifference(size);
		for (size_t i = 0; i < size; i++) {
			actualDifference[i] = currMask[i] ^ nextMask[i];
		}

		//Get the value that was computed in the offline phase.
		auto committedDifference = circuitBundle->getPlacementMaskDifference();

		//If both values are not equal, this is a cheating. Throw a cheating exception.
		if (BinaryUtils::checkEquals(*committedDifference, actualDifference) == false) {
			throw CheatAttemptException("committed delta between signals differ from actual signals!");
		}
	}
}

/**
* Verifies that the received decommitments on the x input keys are correct.
* In case they are, extract the keys and sets them in the circuits.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
*/
void OnlineProtocolP2::receiveAndVerifyXInputKeys(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage) {
	//The labels are equal in all circuits.
	size_t numberOfInputsX = bucket->getLimitedBundleAt(0)->getInputLabelsXSize();
	auto size = input.size();
	int hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();

	//For each circuit, verify the decommitment on the input keys.
	auto bucketSize = bucket->size();
	for (size_t j = 0; j < bucketSize ; j++) {
		//Get the circuit, commitment mask and commitments on the keys.
		auto circuitBundle = bucket->getLimitedBundleAt(j);
		vector<byte> observedMask(size);
		memcpy(observedMask.data(), evaluationPackage.getPlacementMask().data() + j*size, size);
		auto commitmentMask = circuitBundle->getCommitmentMask();
		auto commitments = circuitBundle->getCommitmentsX();

		//Copy the commitments, values and random values to a one dimension array in order to get better performance in the native implementation.
		vector<byte> commitmentsArray(numberOfInputsX * hashSize);
		vector<byte> randoms(numberOfInputsX * hashSize);
		vector<byte> values(numberOfInputsX * keyLength);

		auto decommitmentRandoms = evaluationPackage.getRandomDecommitmentXInputKey();
		auto decommitmentX = evaluationPackage.getXDecommitmentXInputKey();

		for (size_t i = 0; i < numberOfInputsX; i++) {
			auto com = commitments->getCommitments();// (i, observedMask[i]);
			
			memcpy(commitmentsArray.data() + i*hashSize, com->data() + i * 2 * hashSize + observedMask[i] * hashSize, hashSize);
			memcpy(randoms.data() + i*hashSize, decommitmentRandoms.data() + hashSize * (j*numberOfInputsX + i), hashSize);
			memcpy(values.data() + i*keyLength, decommitmentX.data() + keyLength*(j*numberOfInputsX + i), keyLength);
		}

		//Checks that the random values and committed values are indeed lead to the commitments values.
		bool valid = verifyDecommitment(CryptoPrimitives::getHash().get(), commitmentsArray, randoms, values);

		//If the verify failed, there is a cheating. Throw an exception.
		if (valid == false) {
			throw CheatAttemptException("incorrect decommitment!");
		}

		//Xor the keys with the commitment mask to get the x keys.
		auto valuesBlocks = convertByteVectorToBlockArray(&values);
		xorKeysWithMask(valuesBlocks, values.size() / SIZE_OF_BLOCK, commitmentMask);

		//Set x keys to the circuit.
        auto temp = convertBlockArrayToByteVector(valuesBlocks, values.size() / SIZE_OF_BLOCK);
		circuitBundle->setXInputKeys(temp);
		_mm_free(valuesBlocks);

	}
}

/**
* Extract from the received package the encrypted proof of cheating.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
*/
void OnlineProtocolP2::receiveEncryptedProof(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage) {
	auto numberOfOutputs = bucket->getLimitedBundleAt(0)->getOutputLabelsSize();
	proofCiphers.resize(numberOfOutputs);

	//For each output label and for each circuit, get the encrypted proofs.
	for (size_t v = 0; v < numberOfOutputs; v++) {
		proofCiphers[v].resize(bucket->size());
		auto bucketSize = bucket->size();
		for (size_t j = 0; j < bucketSize ; j++) {
			proofCiphers[v][j].resize(2);
			for (int k = 0; k < 2; k++) {
				proofCiphers[v][j][k] = evaluationPackage.getXoredProof(v, j, k, bucket->size(), keyLength);
			}
		}
	}

	// receive H(D)
	hashedProof = SecretKey(evaluationPackage.getHashedProof(), "");
}

/**
* Computes the main circuit.
* @param bucket The bucket to work on.
*/
void OnlineProtocolP2::computeEvaluationCircuits(const shared_ptr<BucketLimitedBundle> & bucket) {
	//Get the circuits to work on.
	auto garbledCircuits = mainExecution.getCircuits();

	//Create a compute routine.
	computeRoutine.reset(new OnlineComputeRoutine(garbledCircuits, bucket, proofCiphers, hashedProof));
	//Computes the circuits.
	computeRoutine->computeCircuits();
	//Check if all circuits return the same output.
	evaluationResult = computeRoutine->runOutputAnalysis();

	//If found a proof of cheating, get it. Else, get a dummy key.
	proofOfCheating = computeRoutine->getProofOfCheating();
}

/**
* Verifies the decommitment on the output keys that were received from p1.
* @param bucket The bucket to work on.
* @param evaluationPackage The message that was received from p1.
*/
void OnlineProtocolP2::receiveAndVerifyOutputKeys(BucketLimitedBundle* bucket, EvaluationPackage & evaluationPackage) {

	//Get the proof of cheating. 
	SecretKey realProofOfCheating(evaluationPackage.getProofOfCheating(), "");
	block realPOC;
	memcpy(&realPOC, realProofOfCheating.getEncoded().data(), realProofOfCheating.getEncoded().size());

	//Compute the hash function on the proof of cheating and check that the result is equal to the given one.
	auto hash = CryptoPrimitives::getHash();
	auto hashOfRealProof = KeyUtils::hashKey(&realProofOfCheating, hash.get(), CryptoPrimitives::getHKDF().get(), keyLength);
	if (!KeyUtils::compareKeys(&hashOfRealProof, &hashedProof)) {
		throw CheatAttemptException("H(D) given previously does not equal H() on the decommitted D!");
	}

	auto numberOfOutputs = bucket->getLimitedBundleAt(0)->getOutputLabelsSize();

	size_t correctCircuit = -1;
	//for each circuit in the bucket, 
	auto bucketSize = bucket->size();
    auto hashSize = hash->getHashedMsgSize();
	vector<byte> hashValArray(hashSize);

	auto decomX = evaluationPackage.getXDecommitmentOutputKey();// getDecommitmentToOutputKey(j, numberOfOutputs, keyLength, hashSize);
	auto decomR = evaluationPackage.getRandomDecommitmentOutputKey();

	for (size_t j = 0; j < bucketSize; j++) {
		bool allOutputsAreCorrect = true;

		auto commitment = bucket->getLimitedBundleAt(j)->getCommitmentsOutputKeys();

		//Get the decommitment values and verify them.
		//auto kVal = cmtReceiver->verifyDecommitment(commitment, &decom);
		vector<byte> kVal(decomX.begin() + keyLength * j* numberOfOutputs * 2, decomX.begin() + (keyLength * numberOfOutputs * 2) * (j + 1));
		hash->update(decomR, hashSize * j, hashSize);
		hash->update(kVal, 0, keyLength * 2 * numberOfOutputs);
		hash->hashFinal(hashValArray, 0);

		//Checks that c = H(r,x)
		if (*commitment != hashValArray)
			throw CheatAttemptException("incorrect decommitment!");

		vector<block> decryptions(2);
		vector<block> keys(2);
		//For each output key, get the corresponding keys.
		for (size_t v = 0; v < numberOfOutputs; v++) {
			
			for (int k = 0; k < 2; k++) {
				memcpy(&keys[k], kVal.data() + (v * 2 + k)*keyLength, keyLength);
				decryptions[k] = _mm_xor_si128(keys[k], proofCiphers[v][j][k]);
			}

			//allOutputsAreCorrect = checkCircuitOutputsFromCompute(keys, j, v);
			auto garbledOutput = computeRoutine->getComputedOutputWires(j);
			block key;
			memcpy(&key, (byte*)garbledOutput + v*keyLength, keyLength);

			if (!BinaryUtils::equalBlocks(key, keys[0]) && !BinaryUtils::equalBlocks(key, keys[1])) {
				allOutputsAreCorrect = false;
			}

			//Xor both result of the above decryptions.
			block result = _mm_xor_si128(decryptions[0], decryptions[1]);

			//Compare the result to the proof of cheating. In case they are not equal, throw a cheating exception.
			if (!BinaryUtils::equalBlocks(result, realPOC)) {
				throw CheatAttemptException("the xor of the output keys does not give the real proof for label v = " + v);
			}
		}

		if (allOutputsAreCorrect) {
			correctCircuit = j;
		}
	}

	if (correctCircuit != -1) {
        computeRoutine->setCorrectCircuit(correctCircuit);
		mainOutput = computeRoutine->getOutput();
	}
}

/*bool OnlineProtocolP2::checkCircuitOutputsFromCompute(vector<block> & keys, size_t circuitIndex, size_t wireIndex) {
	auto garbledOutput = computeRoutine->getComputedOutputWires(circuitIndex);
	block key;
	memcpy(&key, (byte*)garbledOutput + wireIndex*keyLength, keyLength);

	if (BinaryUtils::checkEquals(key, keys[0]) || BinaryUtils::checkEquals(key, keys[1])) {
		return true;
	}
	return false;
}
*/
/**
* Computes the cheating recovery circuit.
* @param bucket The bucket to work on.
*/
void OnlineProtocolP2::computeCheatingRecoveryCircuit(const shared_ptr<BucketLimitedBundle> & bucket) {
	//Get the circuits to work on.
	auto garbledCircuits = crExecution.getCircuits();

	//Create an array of size numCircuits and put in "0" in each cell. 
	//"0" means that the circuit in this index is evaluated circuit.
	auto bucketSize = bucket->size();
	vector<byte> selection(bucketSize);
	for (size_t i = 0; i < bucketSize; i++) {
		selection[i] = 0;
	}
	CutAndChooseSelection dummySelection(selection);
	//Create the majority compute routine.
	MajoriryComputeRoutine computeRoutineNew(dummySelection, garbledCircuits, bucket);

	//Computes the circuits.
	computeRoutineNew.computeCircuits();

	//get majority output.
	computeRoutineNew.runOutputAnalysis();

	//Get the majority output.
	crOutput = computeRoutineNew.getOutput();
}
/**
* Constructor that sets the parameters.

*/
OnlineProtocolP2::OnlineProtocolP2(int argc, char* argv[]) : Protocol ("OnlineMaliciousYao", argc, argv) {

    const string HOME_DIR = "../..";
    //read config file data and set communication config to make sockets.
    CommunicationConfig commConfig(HOME_DIR + arguments["partiesFile"], 2, io_service);
    auto commParty = commConfig.getCommParty();

    cout << "\nP2 start communication\n";

    //make connection
    for (int i = 0; i < commParty.size(); i++)
        commParty[i]->join(500, 5000);


    int B1 = stoi(arguments["b1"]);
    int B2 = stoi(arguments["b2"]);
    auto mainBC = make_shared<BooleanCircuit>(new scannerpp::File(HOME_DIR + arguments["circuitFile"]));
    auto crBC = make_shared<BooleanCircuit>(new scannerpp::File(HOME_DIR + arguments["circuitCRFile"]));

    vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit(B1);
    vector<shared_ptr<GarbledBooleanCircuit>> crCircuit(B2);

    for (int i = 0; i<B1; i++) {
        mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(HOME_DIR + arguments["circuitFile"],
                                    GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
    }

    for (int i = 0; i<B2; i++) {
        crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(HOME_DIR + arguments["circuitCRFile"], mainCircuit[0]->getNumberOfGates()).create());
    }

    mainExecution = ExecutionParameters(mainBC, mainCircuit, stoi(arguments["n1"]), stoi(arguments["s1"]), B1, stod(arguments["p1"]));
    crExecution = ExecutionParameters(crBC, crCircuit, stoi(arguments["n2"]), stoi(arguments["s2"]), B2, stod(arguments["p2"]));

    // we load the bundles from file
    mainMatrix = new KProbeResistantMatrix();
    crMatrix = new KProbeResistantMatrix();
    mainMatrix->loadFromFile(HOME_DIR + arguments["mainMatrix"]);
    crMatrix->loadFromFile(HOME_DIR + arguments["crMatrix"]);

    //Set and initialize the parameters

	this->keyLength = CryptoPrimitives::getAES()->getBlockSize();

	this->channel = commParty[0];
	auto hash = CryptoPrimitives::getHash();
	cmtReceiver.reset(new CmtSimpleHashReceiver(channel, hash, hash->getHashedMsgSize()));

}

void OnlineProtocolP2::setBuckets(const shared_ptr<BucketLimitedBundle> & mainBucket, const shared_ptr<BucketLimitedBundle> & crBucket){
    this->mainBucket = mainBucket;
    this->crBucket = crBucket;
}

/**
* Executes the second party of the online protocol.<p>
* basically, it computes the main circuit and than the cheating recovery circuit.
*/
void OnlineProtocolP2::runOnline() {

	//LogTimer timer = new LogTimer("Evaluating Main circuit");
    //Compute the main circuits part.
	evaluateMainCircuit();
	//timer.stop();
    //timer.reset("Evaluating CR circuit");
	//Compute the cheating recovery circuits part.
	evaluateCheatingRecoveryCircuit();
    //timer.stop();
}



/**
* Get the output of the protocol.
*/
CircuitOutput OnlineProtocolP2::getOutput() {
	auto bc = mainExecution.getBooleanCircuit();

	//In case the circuit computation returned valid output this is the output of the protocol and return it.
	if (evaluationResult == CircuitEvaluationResult::VALID_OUTPUT && mainOutput.size() != 0) {
		return CircuitOutput(mainOutput);
	}

	// If we got here, cheating was detected. Therefore we must have obtained P1's input.
	if (crOutput.size() == 0) {
		throw invalid_argument("Illegal Argument Exception");
	}

	// We must use the output received in the GoToCourt stage as the input of P1 to the UNGARBLED circuit.
	auto inputIndices = bc->getInputWireIndices(1);

	//Create the input of p1 according to the cheating recovery output.
	map<int, Wire> inputP1;
	auto indicesSize = inputIndices.size();

	for (size_t i = 0; i<indicesSize; i++) {
		inputP1[inputIndices[i]] = Wire(crOutput[i]);
	}

	//Get the input to p2 from the circuit input.
	auto p2Input = *input.getInputVectorShared();
	inputIndices = bc->getInputWireIndices(2);

	//Create the input of p1 according to the cheating recovery output.
	map<int, Wire> inputP2;
	indicesSize = inputIndices.size();
    for (size_t i = 0; i<indicesSize; i++) {
		inputP2[inputIndices[i]] = Wire(p2Input[i]);
	}

	//Set the inputs.
	bc->setInputs(inputP1, 1);
	bc->setInputs(inputP2, 2);

	//Compute the boolean circuit
	auto output = bc->compute();

	//Convert the output into a byte array.
	auto outputIndices = bc->getOutputWireIndices();
	auto outputSize = outputIndices.size();
	vector<byte> byteOutput(outputSize);
	for (size_t i = 0; i<outputSize; i++) {
		byteOutput[i] = output[outputIndices[i]].getValue();
	}

	//Create an output object using the converted array.
	return CircuitOutput(byteOutput);
}

