#include "../../../include/OfflineOnline/subroutines/OnlineComputeRoutine.hpp"

/**
* Computes the circuits from the start point to the end point in the circuit list.
* @param from The first circuit in the circuit list that should be computed.
* @param to The last circuit in the circuit list that should be computed.
*/
void OnlineComputeRoutine::computeCircuit(size_t from, size_t to, int index) {
   //Compute each circuit in the range.
	for (size_t i = from; i<to; i++) {
		auto circuitBundle = bucket->getLimitedBundleAt(i);
		//Set the garbled and translation tables.
		circuits[index]->setGarbledTables(circuitBundle->getGarbledTables());
		circuits[index]->setTranslationTable(circuitBundle->getTranslationTable());

		//Copy the x and y inputs to one big inputs array.
		int numberOfInputs = circuits[index]->getNumberOfInputs();
        vec_byte_align inputs;

		vector<byte> xInputs = circuitBundle->getXInputKeys();
		vector<byte> yInputs = circuitBundle->getYInputKeys();
        inputs.insert(inputs.begin(), xInputs.begin(), xInputs.end());
		inputs.insert(inputs.end(), yInputs.begin(), yInputs.end());
        //Compute the circuit.
		block* garbledOutput = (block *)_mm_malloc(sizeof(block) * circuits[index]->getNumberOfOutputs(), SIZE_OF_BLOCK);
        circuits[index]->compute((block*) inputs.data(), garbledOutput);
        //Save the output in the outputs map.
		computedOutputWires[i] = garbledOutput;
		vector<byte> binOutput(circuits[index]->getNumberOfOutputs());
		circuits[index]->translate(garbledOutput, binOutput.data());
        translations[i] = binOutput;
	}
}

/**
* Extract proof of cheating for the given wire index.
* If there was no cheating, return null key.
* @param wireIndex The wire index to check for cheating.
* @return the proof of cheating in case there was a cheating; null, otherwise.
* @throws InvalidKeyException
* @throws InvalidInputException
*/
SecretKey OnlineComputeRoutine::extractProofOfCheating(int wireIndex) {
	block* k0 = NULL, *k1 = NULL;

	int j0 = -1;
	int j1 = -1;

	size_t numCircuits = bucket->size();
	//for each circuit, get the output of the given wire.
	//If there are two circuits that returned different output, check that these output values reveals the same proof
	//(using the received proof ciphers).
	//Use the generated proof in order to get the hashed result and check if it matches the received one.
	for (size_t j = 0; j < numCircuits; j++) {

        		//Get the index of the output.
		byte wireValue = translations[j][wireIndex];
		block* computedWire = computedOutputWires[j] + wireIndex;

		if (0 == wireValue) {
			k0 = computedWire;
			j0 = j;
		}
		else {
			k1 = computedWire;
			j1 = j;
		}

		//If there is a different circuit that return a different key, use them to get the proof of cheating.
		if ((NULL != k0) && (NULL != k1)) {
            auto p0 = _mm_xor_si128(*k0, proofCiphers[wireIndex][j0][0]);
			auto p1 = _mm_xor_si128(*k1, proofCiphers[wireIndex][j1][1]);


			auto temp = _mm_xor_si128(p0, p1);
			SecretKey proof((byte*)&temp, SIZE_OF_BLOCK, "");

			//Hash the proof and compare the result to the received hash result. 
			//If equal, then there was a cheating.
			SecretKey hashOnProof = KeyUtils::hashKey(&proof, hash.get(), kdf.get(), keyLength);

			if (KeyUtils::compareKeys(&hashOnProof, &hashedProof)) {
                return proof;
			}
		}
	}
	return SecretKey();
}

/**
* A constructor that sets the given parameters.
* @param garbledCircuits The circuits to work on. There is one circuit per thread.
* @param primitives Primitives objects to use in the compute step.
* @param enc Used to extract the proof of cheating.
* @param proofCiphers Used to extract the proof of cheating.
* @param hashedProof Used to extract the proof of cheating.
*/
OnlineComputeRoutine::OnlineComputeRoutine(vector<shared_ptr<GarbledBooleanCircuit>> & garbledCircuit, const shared_ptr<BucketLimitedBundle> & bucket, 
	vector<vector<vector<block>>> & proofCiphers, SecretKey & hashedProof) {
	//Sets the given prameters.
	circuits = garbledCircuit;
	this->bucket = bucket;

	hash = CryptoPrimitives::getHash();
	kdf = CryptoPrimitives::getHKDF();
	aes = CryptoPrimitives::getAES();
	prg = CryptoPrimitives::getPrg();
	keyLength = aes->getBlockSize();

	this->proofCiphers = proofCiphers;
	this->hashedProof = hashedProof;

	computedOutputWires.resize(bucket->size());
	translations.resize(bucket->size());
}

void OnlineComputeRoutine::computeCircuits() {
	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < circuits.size()) ? CryptoPrimitives::getNumOfThreads() : bucket->size();

        vector<thread> threads;

		//Calculate the number of circuit in each thread and the remainder.
		int numOfCircuits = (circuits.size() + threadCount - 1)/ threadCount;
        int remain  = circuits.size();

        //Create the threads and assign to each one the appropriate circuits.
		for (int j = 0; j < threadCount; j++) {
            if (remain >= numOfCircuits){
				threads.push_back(thread(&OnlineComputeRoutine::computeCircuit, this, j*numOfCircuits, (j + 1)*numOfCircuits, j));
                remain -= numOfCircuits;
			}
			else if (remain > 0){
				threads.push_back(thread(&OnlineComputeRoutine::computeCircuit, this, j*numOfCircuits, circuits.size(), j));
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
		computeCircuit(0, bucket->size(), 0);
	}
}

CircuitEvaluationResult OnlineComputeRoutine::runOutputAnalysis()  {

	// For each output wire
	int outputSize = circuits[0]->getNumberOfOutputs();
	for (int i = 0; i < outputSize; i++) {
		// Get the set of valid outputs received on this wire.
		proofOfCheating = extractProofOfCheating(i);

		// If we received two different values on the same wire, it means the other party is cheating.
		if (proofOfCheating.getEncoded().size() != 0) {
			return CircuitEvaluationResult::FOUND_PROOF_OF_CHEATING;
		}
	}

	//In case there was no cheating, create dummy key.
	vector<byte> proof;
	prg->getPRGBytes(proof, 0, SIZE_OF_BLOCK); // D
	SecretKey tmp(proof, "");
	proofOfCheating = tmp;
	return CircuitEvaluationResult::VALID_OUTPUT;
}

vector<byte> OnlineComputeRoutine::getOutput() {
	//If there was no cheating, all circuits output the same result. 
	//Take it from the first circuit.
    return translations[correctCircuit];
}

/**
* Computes the circuits from the start point to the end point in the circuit list.
* @param from The first circuit in the circuit list that should be computed.
* @param to The last circuit in the circuit list that should be computed.
*/
void MajoriryComputeRoutine::computeCircuit(size_t from, size_t to, int index) {

	//Compute each circuit in the range.
	for (size_t i = from; i<to; i++) {
        auto circuitBundle = bucket->getLimitedBundleAt(i);

		//Get the master key.
		auto masterKeyShares = circuitBundle->getYInputKeys();
		auto numberOfSecretSharingLabels = circuitBundle->getInputLabelsY2Size();

		block masterKey, temp;
		memcpy(&masterKey, masterKeyShares.data(), keyLength);

		for (size_t j = 1; j < numberOfSecretSharingLabels; j++) {
			memcpy(&temp, masterKeyShares.data() + j*keyLength, keyLength);
			masterKey = _mm_xor_si128(masterKey, temp);
		}
        //Set the garbled and translation tables.
		circuits[index]->setGarbledTables(circuitBundle->getGarbledTables());
		circuits[index]->setTranslationTable(circuitBundle->getTranslationTable());
        //Copy all inputs to one big inputs array.
		int numberOfInputs = circuits[index]->getNumberOfInputs();
        vec_byte_align inputs;// inputs(numberOfInputs * keyLength);
		vector<byte> xInputs = circuitBundle->getXInputKeys();
		//memcpy(inputs.data(), xInputs.data(), xInputs.size());
		//memcpy(inputs.data() + xInputs.size(), &masterKey, BLOCK_SIZE);
		inputs.insert(inputs.begin(), xInputs.begin(), xInputs.end());
		inputs.insert(inputs.end(), (byte*) &masterKey,  (byte*) &masterKey + SIZE_OF_BLOCK);
        //Compute the circuit.
		block* garbledOutput = (block *)_mm_malloc(sizeof(block) * circuits[index]->getNumberOfOutputs(), SIZE_OF_BLOCK);
		circuits[index]->compute((block*)inputs.data(), garbledOutput);
        //Translate the garbled output.
		vector<byte> binOutput(circuits[index]->getNumberOfOutputs());
		circuits[index]->translate(garbledOutput, binOutput.data());
        //Save the boolean output in the outputs map.
		allOutputs[i] = binOutput;
		_mm_free(garbledOutput);
	}
}

/**
* Returns the output with the highest counter.
* @param map Contains for each output wire all the optional outputs.
*/
byte MajoriryComputeRoutine::getKeyWithMaxValue(vector<int> & map) {

	byte maxValue = (byte)0;
	int maxindex = -1;

	//For each value in the map, check if it is higher than the maximum.
	//If it is, put it as the maximum.
	for (int i=0; i<map.size(); i++){
		if (maxValue < map[i]) {
			maxValue = map[i];
            maxindex = i;
		}
	}

	//Return the value that has the higher counter. 
	return maxindex;
}
/**
* A constructor that sets the given parameters.
* @param selection Indicates which circuit is checked and which is evaluated.
* @param garbledCircuits The circuits to work on. There is one circuit per thread.
* @param primitives Contains some primitives objects to use during the protocol.
*/
MajoriryComputeRoutine::MajoriryComputeRoutine(CutAndChooseSelection & selection, vector<shared_ptr<GarbledBooleanCircuit>> & garbledCircuits, shared_ptr<BucketLimitedBundle> bucket)
	: selection(selection) {
	circuits = garbledCircuits;
	this->bucket = bucket;
	keyLength = CryptoPrimitives::getAES()->getBlockSize();
	allOutputs.resize(bucket->size());
	vector<byte> a;
	for(int i=0; i<bucket->size(); i++){
		allOutputs[i] = a;
	}
}

void MajoriryComputeRoutine::computeCircuits() {
	auto sizeOfEvalCircuits = selection.getEvalCircuits().size();
	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < circuits.size()) ? CryptoPrimitives::getNumOfThreads() : bucket->size();

        vector<thread> threads;

        //Calculate the number of circuit in each thread and the remainder.
        int numOfCircuits = (bucket->size() + threadCount - 1)/ threadCount;
        int remain  = bucket->size();

        //Create the threads and assign to each one the appropriate circuits.
		for (int j = 0; j < threadCount; j++) {
            if (remain >= numOfCircuits){
				threads.push_back(thread(&MajoriryComputeRoutine::computeCircuit, this, j*numOfCircuits, (j + 1)*numOfCircuits, j));
                remain -= numOfCircuits;
			}
			else if (remain > 0){
				threads.push_back(thread(&MajoriryComputeRoutine::computeCircuit, this, j*numOfCircuits, circuits.size(), j));
                remain = 0;
			}
		}

        //Wait until all threads finish their job.
        for (int j = 0; j < threads.size(); j++) {
            threads[j].join();
            threads[j].~thread();
        }
		//In case no thread should be created, verify all the circuits input directly.
	}
	else {
		computeCircuit(0, bucket->size(), 0);
	}
}

CircuitEvaluationResult MajoriryComputeRoutine::runOutputAnalysis() {
	int numberOfOutputs = circuits[0]->getNumberOfOutputs();
    //This map will hold for each wire the number of times that each output has been received.
    vector<vector<int>> counterMap(numberOfOutputs, vector<int>(2));

    bool hasOutput = false;
	// For each circuit and each wire, count how many times each value was received on each wire.
	for (auto j : selection.getEvalCircuits()) {
		if (allOutputs[j].empty()) {
			// No output for circuit j, skip.
			continue;
		}

        hasOutput = true;

		//Get the output of this eval circuit.
		auto output = allOutputs[j];
		//For each wire index,
		for (int w = 0; w < numberOfOutputs; w++) {
			byte wireValue = output[w];

			// Increase the counter of this value by one.
            counterMap[w][wireValue]++;
		}
	}

	//If all output wires didn't get outputs, there is no majority.
	if (!hasOutput) {
		// No circuits delivered output, so there is no majority.
		return CircuitEvaluationResult::INVALID_WIRE_FOUND;
	}

	//Put the majority output in the majorityOutput array.
	majorityOutput.resize(numberOfOutputs);
	//For each output wire, get the map containing the optional outputs and put in the majority array the output with the highest counter.
	for (int w = 0; w<numberOfOutputs; w++) {
		auto counters = counterMap[w];
		majorityOutput[w] = getKeyWithMaxValue(counters);
	}

	//Returns valid output.
	return CircuitEvaluationResult::VALID_OUTPUT;
}