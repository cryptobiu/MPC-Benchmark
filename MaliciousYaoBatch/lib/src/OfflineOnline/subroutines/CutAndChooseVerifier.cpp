#include "../../../include/OfflineOnline/subroutines/CutAndChooseVerifier.hpp"

CutAndChooseVerifier::CutAndChooseVerifier(const shared_ptr<ExecutionParameters> & execution, vector<shared_ptr<CommParty>> & channel,
	const shared_ptr<BundleBuilder> & bundleBuilder, string filePrefix, int labelsY2Size)
{
	//Sets the class member s using the given values.
	this->execution = execution;
	this->channel = channel;
	this->bundleBuilder = bundleBuilder;
	numCircuits = execution->getNumCircuits();

	//Do the circuits selection.
	selectCutAndChoose(execution->getCheckCircuits());

	//DO the circuits mapping.
	CryptoPrimitives::getRandom()->getPRGBytes(seedMapping, 0, SIZE_OF_BLOCK);
	bucketMapping = make_shared<BucketMapping>(selection->getEvalCircuits(),
		execution->getNumberOfExecutions(), execution->getBucketSize(), seedMapping);

	//Create the commitment objects.
	cmtSender = new  CmtSimpleHashCommitter(this->channel[0], CryptoPrimitives::getRandom(), CryptoPrimitives::getHash(),
		CryptoPrimitives::getHash()->getHashedMsgSize());
	cmtReceiver = new CmtSimpleHashReceiver(this->channel[0], CryptoPrimitives::getHash(),
		CryptoPrimitives::getHash()->getHashedMsgSize());

	//Get the circuit indices.
	auto gbc = execution->getCircuit(0);
	outputLabelsSize = gbc->getOutputIndices().size();
	labelsXSize = gbc->getInputWireIndices(1).size();
	this->labelsY2Size = (labelsY2Size>0) ? labelsY2Size : gbc->getInputWireIndices(2).size();

	//Create the commitments arrays.
	commitmentToSeed = vector<shared_ptr<CmtCCommitmentMsg>>(numCircuits);
	commitmentToCommitmentMask = vector<shared_ptr<CmtCCommitmentMsg>>(numCircuits);
	commitmentsX.resize(numCircuits);
	commitmentsY1Extended.resize(numCircuits);
	commitmentsY2.resize(numCircuits);
	commitmentsOutput = vector<shared_ptr<CmtCCommitmentMsg>>(numCircuits);
	decommitmentsOutput = vector<shared_ptr<CmtCDecommitmentMessage>>(numCircuits);
	diffCommitments = vector<shared_ptr<DifferenceCommitmentReceiverBundle>>(numCircuits);

	filePrefix = filePrefix;
	buckets = NULL;
}

void CutAndChooseVerifier::run()
{
	//LogTimer timer("receiveGarbledCircuits");
	//Receive all garbled circuits from the cut and choose prover.
	receiveGarbledCircuits();
	//timer.stop();
	//timer.reset("commitToCutAndChoose");
	//Send the commitments of the circuits selection and mapping.
	commitToCutAndChoose();
	//timer.stop();
	//timer.reset("receiveCommitments");
	//Receive the commitments needed by the protocol (on keys, masks, seed, etc).
	receiveCommitments();
	//timer.stop();
	//timer.reset("revealCutAndChoose");
	//Send to the cut and choose prover the circuit selection and mapping.
	revealCutAndChoose();
	//timer.stop();
	//timer.reset("verifyCheckCircuits");
	//Verify the checked circuits by verifying the commitments of the seeds, masks, keys of the checked circuits.
	verifyCheckCircuits();
	//timer.stop();
	//timer.reset("putCircuitsInBuckets");
	//Put all evaluated circuits in buckets according to the received mapping.
	putCircuitsInBuckets();
	//timer.stop();
	//timer.reset("verifyCorrectnessOfPlacementMasks");
	//Verify the placement masks by verifying the decommitments of the diff protocol.
	verifyCorrectnessOfPlacementMasks();
	//timer.stop();
}

shared_ptr<BucketLimitedBundleList> CutAndChooseVerifier::getBuckets()
{
	//In case the buckets were not created yet, create them.
	if (NULL == buckets) {
		putCircuitsInBuckets();
	}
	//Return the filled buckets.
	return buckets;
}

void CutAndChooseVerifier::putCircuitsInBuckets()
{
	if (bucketMapping == NULL) {
		throw invalid_argument("Illegal Argument Exception");
	}

	// Create the bucket list and add each evaluated circuit.
	this->buckets = make_shared<BucketLimitedBundleList>(execution, bucketMapping);
	for (const auto j : selection->getEvalCircuits())
	{
		shared_ptr<LimitedBundle> bundle;
		//Create a LimitedBundle from the received garbled table, translation table, wires' indices and commitments.
		if (filePrefix.empty())
		{
			bundle = make_shared<LimitedBundle>(this->garbledTables[j], garbledTablesSize[j], translationTables[j], 
				labelsXSize, labelsY2Size, outputLabelsSize, commitmentsX[j], commitmentsY1Extended[j], commitmentsY2[j], 
				commitmentsOutput[j].get(), decommitmentsOutput[j], diffCommitments[j], 
				filePrefix);
		}
		else
		{
			string newFilePrefix = filePrefix + "GarbledTables." + to_string(j);
			bundle = make_shared<LimitedBundle>(this->garbledTables[j], garbledTablesSize[j], translationTables[j],
				labelsXSize, labelsY2Size, outputLabelsSize, commitmentsX[j], commitmentsY1Extended[j], commitmentsY2[j],
				commitmentsOutput[j].get(), decommitmentsOutput[j], diffCommitments[j],
				newFilePrefix);
		}

		this->buckets->add(bundle, j);
	}
}

void CutAndChooseVerifier::selectCutAndChoose(int selectionSize)
{
	// check that the number of checked circuit is smaller than the total number of circuits.
	if (!(selectionSize < numCircuits)) {
		throw invalid_argument("Illegal Argument Exception");
	}

	//Create s the selection array. This array will hold "1" for each checked circuit and "0" for each evaluated circuit.
	vector<byte> selectionArray(numCircuits, 0);
	vector<int> circuitSelectionPool(numCircuits);
	iota(circuitSelectionPool.begin(), circuitSelectionPool.end(), 0);

	//shuffle circuitSelectionPool
	auto size = circuitSelectionPool.size();
	for (size_t i = size - 1; i > 0; i--) {
		int index = CryptoPrimitives::getRandom()->getRandom32() % size;
		auto tmp = circuitSelectionPool[i];
		circuitSelectionPool[i] = circuitSelectionPool[index];
		circuitSelectionPool[index] = tmp;
	}

	// Select a circuit randomly from the list of circuits selectionSize times.
	for (int i = 0; i < selectionSize; i++)
	{
		//select an index.
		int selectedCircuit = circuitSelectionPool[i];
		// Set the selectCircuit's index in the selection byte array to be checked (put "1" in this index).
		selectionArray[selectedCircuit] = 1;
	}

	selection = make_shared<CutAndChooseSelection>(selectionArray);
}

void CutAndChooseVerifier::commitToCutAndChoose()
{
	auto temp = selection->asByteArray();
	cmtSender->commit(cmtSender->generateCommitValue(temp), COMMIT_ID_CUT_AND_CHOOSE);
	cmtSender->commit(cmtSender->generateCommitValue(seedMapping), COMMIT_ID_BUCKET_MAPPING);
}

void CutAndChooseVerifier::receiveGarbledCircuits()
{
	//Create place to hold all tables.
	if (filePrefix.empty()) {
		garbledTables.resize(numCircuits);
		garbledTablesSize.resize(numCircuits);
	}
	translationTables = vector<vector<byte>>(numCircuits);

	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < numCircuits) ? CryptoPrimitives::getNumOfThreads() : numCircuits;

		vector<thread> threads;

		//Calculate the number of circuit in each thread and the remainder.
		int numOfCircuits = (numCircuits + threadCount - 1)/ threadCount;
		int remain  = numCircuits;

		//Create the threads and assign to each one the appropriate circuits.
		for (int j = 0; j < threadCount; j++) {
			if (remain >= numOfCircuits){
				threads.push_back(thread(&CutAndChooseVerifier::receiveCircuit, this, j*numOfCircuits, (j + 1)*numOfCircuits, j));
				remain -= numOfCircuits;
			}
			else if (remain > 0){
				threads.push_back(thread(&CutAndChooseVerifier::receiveCircuit, this, j*numOfCircuits, numCircuits, j));
				remain = 0;
			}
		}

		//Wait until all threads finish their job.
		for (int j = 0; j < threads.size(); j++) {
			threads[j].join();
			threads[j].~thread();
		}
		//In case no thread should be created, build all the circuits directly.
	}
	else {
		receiveCircuit(0, numCircuits, 0);
	}
}

void CutAndChooseVerifier::receiveCircuit(int from, int to, int threadIndex) {
	for (int j = from; j < to; j++) {
		vector<byte> readGarbledTables;
		//Receive the garbled and translation tables of each circuit.
		if (filePrefix.empty()) {
			channel[threadIndex]->readWithSizeIntoVector(readGarbledTables);
		}
		else {
			//read file and set obj
			ifstream ifs(filePrefix + "GarbledTables." + to_string(j), ifstream::binary);
			boost::archive::binary_iarchive ia(ifs);

			ia >> readGarbledTables;
		}

		garbledTables[j] = (block *)_mm_malloc(readGarbledTables.size(), 16);
		memcpy(garbledTables[j], readGarbledTables.data(), readGarbledTables.size());
		garbledTablesSize[j] = readGarbledTables.size(); // In bytes.

		channel[threadIndex]->readWithSizeIntoVector(translationTables[j]);

	}
}

void CutAndChooseVerifier::receiveCommitments()
{
	//For each circuit, receive the commitments on the seed, mask and keys and put them in the relative commitment array.
	for (int j = 0; j < numCircuits; j++)
	{
		CommitmentsPackage commitments;
		readSerialize(commitments, channel[0].get());

		commitmentToSeed[j] = shared_ptr<CmtCCommitmentMsg>(commitments.getSeedCmt());
		commitmentToCommitmentMask[j] = shared_ptr<CmtCCommitmentMsg>(commitments.getMaskCmt());

		commitmentsX[j] = make_shared<CommitmentBundle>(commitments.getCommitmentsX(), commitments.getCommitmentXIds());
		commitmentsY1Extended[j] = make_shared<CommitmentBundle>(commitments.getCommitmentsY1Extended(), commitments.getCommitmentY1ExtendedIds());
		commitmentsY2[j] = make_shared<CommitmentBundle>(commitments.getCommitmentsY2(), commitments.getCommitmentY2Ids());
		commitmentsOutput[j] = shared_ptr<CmtCCommitmentMsg>(commitments.getCommitmentsOutputKeys());
	}
	
	//Create a new difference protocol.
	diffProtocol = make_shared<CmtWithDifferenceReceiver>(selection, numCircuits, CryptoPrimitives::getStatisticalParameter(),
		channel[0], CryptoPrimitives::getHash());
	diffProtocol->setup(); // Send commitments to K and W, and send ccSelection encrypted

	//Receive the commitments  of the diff protocol.
	DiffCommitmentPackage commitments;
	readSerialize(commitments, channel[0].get());
	
	// Receive commitments to B[0], ..., B[j - 1]
	auto temp = commitments.getDiffCommitments();
	diffProtocol->receiveCommitment(temp);

	for (int j = 0; j < numCircuits; j++) {
		diffCommitments[j] = make_shared<DifferenceCommitmentReceiverBundle>( diffProtocol->getBundle(j));
	}
}

void CutAndChooseVerifier::revealCutAndChoose()
{
	cmtSender->decommit(COMMIT_ID_CUT_AND_CHOOSE);
	cmtSender->decommit(COMMIT_ID_BUCKET_MAPPING);
}

void CutAndChooseVerifier::verifyCheckCircuits()
{
	//Receive the decommitments.
	DecommitmentsPackage decommitments;
	readSerialize(decommitments, channel[0].get());
	
	int counter = 0;
	//For each checked circuit:
	for (const auto j : selection->getCheckCircuits())
	{
		//Verify the seed and commitment mask.
		auto seed = cmtReceiver->generateBytesFromCommitValue(cmtReceiver->verifyDecommitment(
			commitmentToSeed[j].get(), decommitments.getIdDecommitment(counter).get()).get());
		
		auto commitmentMask = cmtReceiver->generateBytesFromCommitValue(cmtReceiver->verifyDecommitment(
			commitmentToCommitmentMask[j].get(), decommitments.getMaskDecommitment(counter).get()).get());

		//Build the circuit using the verified seed.
		auto circuitBundle = bundleBuilder->build(make_shared<vector<byte>>(seed), CryptoPrimitives::getHash());

		//Check that the verified mask is equal to the generated mask.
		if (!equal(commitmentMask.begin(), commitmentMask.end(), circuitBundle->getCommitmentMask()->begin()))
		{
			throw CheatAttemptException("decommitment of commitmentMask does not match the decommitted seed!");
		}
		block* garbledTable = NULL;
		size_t garbledTableSize = 0;
		if (filePrefix.empty())
		{
			garbledTable = garbledTables[j];
			garbledTableSize = garbledTablesSize[j];
		}
		else
		{
			string tablesFile = filePrefix + "GarbledTables." + to_string(j);
			//read outputWires to vector<byte> align to 16 with no destractor
			vector<byte, aligned_allocator_no_destructor<byte, SIZE_OF_BLOCK>> readGarbledTables;
			{
				//read file and set obj
				ifstream ifs(tablesFile, ifstream::binary);
				boost::archive::binary_iarchive ia(ifs);

				ia >> readGarbledTables;
			}

			//convert from vector<byte> to block*
			garbledTable = (block*)&readGarbledTables[0];
			garbledTableSize = readGarbledTables.size();
		}

		auto tableCircuit = circuitBundle->getGarbledTables();
		if (circuitBundle->getGarbledTableSize() != garbledTableSize)
		{
			throw CheatAttemptException("garbled tables does not match the size of the decommitted seed!");
		}
		if (!equalBlocksArray(tableCircuit, garbledTable, garbledTableSize / 16))
		{
			throw CheatAttemptException("garbled tables does not match the decommitted seed!");
		}

		if (!equal(translationTables[j].begin(), translationTables[j].end(), circuitBundle->getTranslationTable().begin()))
		{
			throw CheatAttemptException("translation tables does not match the decommitted seed!");
		}

		//Verify the keys commitments. Throw exception in case of difference.
		*circuitBundle->getCommitmentsX() == *commitmentsX[j];

		//In case this is not a cheating recovery circuit, we know the secret and can verify the commitments order.
		// Otherwise we cannot verify.
		auto in = dynamic_pointer_cast<CheatingRecoveryBundleBuilder>(bundleBuilder);
		if (in == NULL)
		{
			//Throw exception in case of difference.
			//*circuitBundle->getCommitmentsY1Extended() == *commitmentsY1Extended[j];
			*circuitBundle->getCommitmentsY2() == *commitmentsY2[j];
		}

		//TODO - delete dynamic_pointer_cast<CmtSimpleHashCommitmentMessage> - use directly
		auto m1 = dynamic_pointer_cast<CmtSimpleHashCommitmentMessage>(commitmentsOutput[j]);
		auto m2 = dynamic_pointer_cast<CmtSimpleHashCommitmentMessage>(circuitBundle->getCommitmentsOutputKeys());
		if (!(m1->toString() == m2->toString()))
		{
			//In case the commitments are different, throw an exception.
			throw CheatAttemptException("commitments differ");
		}

		// Receive decommitments of the difference protocol.
		diffProtocol->receiveDecommitment(j, counter, decommitments);

		counter++;
	}
}

void CutAndChooseVerifier::verifyCorrectnessOfPlacementMasks()
{
	if (buckets == NULL) {
		throw invalid_argument("Illegal Argument Exception");
	}

	auto bucketsSize = buckets->size();
	// For each bucket, run the verify stage of the diff protocol (for eval circuits).
	for (size_t i = 0; i < bucketsSize; i++)
	{
		auto bucket = buckets->getBucket(i);
		auto bucketSize = bucket->size();
		vector<shared_ptr<DifferenceCommitmentReceiverBundle>> commitBucket(bucketSize);
		
		for (int j = 0; j < bucketSize; j++)
		{
			commitBucket[j] = bucket->getLimitedBundleAt(j)->getDifferenceCommitmentBundle();
		}

		auto committedDifference = diffProtocol->verifyDifferencesBetweenMasks(commitBucket);

		for (int j = 0; j < bucketSize; j++)
		{
			bucket->getLimitedBundleAt(j)->setPlacementMaskDifference(committedDifference[j]);
		}
	}
}
