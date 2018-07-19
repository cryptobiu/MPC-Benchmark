#include "../../../include/OfflineOnline/subroutines/CutAndChooseProver.hpp"

void CutAndChooseProver::putCircuitsInBuckets()
{
	assert(this->bucketMapping != NULL);

	//Create the bucket list and add each evaluated circuit.
	this->buckets = make_shared<BucketBundleList>(this->execution, this->bucketMapping);
	for (auto j : selection->getEvalCircuits())
	{
		this->buckets->add(this->circuitBundles[j], j);
	}
}

void CutAndChooseProver::constructGarbledCircuitBundles()
{
	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < numCircuits) ? CryptoPrimitives::getNumOfThreads() : numCircuits;

		vector<thread> threads;

		//Calculate the number of circuit in each thread and the remainder.
		int numOfCircuits = (numCircuits + threadCount -1)/ threadCount;
		int remain  = numCircuits;

		//Create the threads and assign to each one the appropriate circuits.
		for (int j = 0; j < threadCount; j++) {
			if (remain >= numOfCircuits){
				threads.push_back(thread(&CutAndChooseProver::buildCircuit, this, j*numOfCircuits, (j + 1)*numOfCircuits, j));
				remain -= numOfCircuits;
			}
			else if (remain > 0){
				threads.push_back(thread(&CutAndChooseProver::buildCircuit, this, j*numOfCircuits, numCircuits, j));
				remain = 0;
			}
		}

		///Wait until all threads finish their job.
		for (int j = 0; j < threads.size(); j++) {
			threads[j].join();
			threads[j].~thread();
		}
	//In case no thread should be created, build all the circuits directly.
	} else {
		buildCircuit(0, numCircuits, 0);
	}
}

void CutAndChooseProver::buildCircuit(int from, int to, int threadIndex)
{
	for (int j = from; j < to; j++) {
		auto temp = CryptoPrimitives::getHashForThreads(threadIndex);
		circuitBundles[j] = bundleBuilders[threadIndex]->build(CryptoPrimitives::getHash()->getHashedMsgSize(),temp); 
		//sendSerialize(circuitBundles[j]->getGarbleTableToSend(), commParty);
		commParty[threadIndex]->writeWithSize(circuitBundles[j]->getGarbleTableToSend().data(), circuitBundles[j]->getGarbleTableToSend().size());
		commParty[threadIndex]->writeWithSize(circuitBundles[j]->getTranslationTable().data(), circuitBundles[j]->getTranslationTable().size());
	}

}

void CutAndChooseProver::receiveCommitmentToCutAndChoose()
{
	selectionCommitment = cmtReceiver->receiveCommitment();
	mappingCommitment =cmtReceiver->receiveCommitment();
}

void CutAndChooseProver::sendCommitments()
{
	//Send a commitment package for each circuit bundle.
	auto length = circuitBundles.size();
	int cmtSize = CryptoPrimitives::getHash()->getHashedMsgSize();
	int s = CryptoPrimitives::getStatisticalParameter();
	for (size_t j = 0; j < length; j++)
	{
		//Create the commitment package.
		//TODO should contain all stuff being sent in this loop, but can't because commitments cause problems. 
		//so right now everthing is sent directly. not efficient!
		CommitmentsPackage cmtPackage(cmtSize, s);

		//Generate the commitment messages on the seed and mask and put them in the commitment package.
		shared_ptr<CmtCommitValue> commitValueSeed = cmtSender->generateCommitValue(*circuitBundles[j]->getSeed());
		shared_ptr<CmtCommitValue> commitValueCommitmentMask = cmtSender->generateCommitValue(*circuitBundles[j]->getCommitmentMask());

		auto seedCmt = cmtSender->generateCommitmentMsg(commitValueSeed, 2 * j);
		cmtPackage.setSeedCmt(seedCmt.get());// COMMIT_ID_SEED

		auto maskCmt = cmtSender->generateCommitmentMsg(commitValueCommitmentMask, 2 * j + 1);
		cmtPackage.setMaskCmt(maskCmt.get());// COMMIT_ID_COMMITMENT_MASK
		//Set the commitments on the keys in the commitment package.
		circuitBundles[j]->getCommitments(cmtPackage);

		sendSerialize(cmtPackage, commParty[0].get());
	}

	//Get the placement masks of each circuit bundle.
	vector<shared_ptr<vector<byte>>> placementMasks(numCircuits);
	for (int j = 0; j < numCircuits; j++)
	{
		placementMasks[j] = circuitBundles[j]->getPlacementMask();
	}

	DiffCommitmentPackage diffPackage(cmtSize, s);

	// TODO java: at the moment the randomness of the CommitWithDifferenceProtocol does not come from the seed.
	diffProtocol = make_shared<CmtWithDifferenceCommitter>(placementMasks, numCircuits,
		CryptoPrimitives::getStatisticalParameter(), commParty[0], CryptoPrimitives::getHash());
	diffProtocol->setup(); // receive commitments to K and W, and receive ccSelection encrypted
	auto diffCommitment = diffProtocol->getCommitments();
	diffPackage.setDiffCommitments(diffCommitment);

	auto size = circuitBundles.size();
	for (size_t j = 0; j < size; j++)
	{
		circuitBundles[j]->setDifferenceCommitmentBundle(diffProtocol->getBundle(j));
	}

	//Send the commitment package.
	sendSerialize(diffPackage, commParty[0].get());
}

void CutAndChooseProver::receiveCutAndChooseChallenge()
{
	auto selectionDecom = cmtReceiver->receiveDecommitment(selectionCommitment->getCommitmentId());
	auto ccSelection = cmtReceiver->generateBytesFromCommitValue(selectionDecom.get());

	auto mappingDecom = cmtReceiver->receiveDecommitment(mappingCommitment->getCommitmentId());
	auto bucketMappingSeed = cmtReceiver->generateBytesFromCommitValue(mappingDecom.get());

	//Create the selection object using the received decommitment.
	selection = make_shared<CutAndChooseSelection>(ccSelection);
	
	//Create the mapping object from the received selection and mapping.
	bucketMapping = make_shared<BucketMapping>(selection->getEvalCircuits(),
		execution->getNumberOfExecutions(), execution->getBucketSize(), bucketMappingSeed);
}

void CutAndChooseProver::proveCheckCircuits()
{
	//Get the indices of the checked circuits.
	auto select = selection->getCheckCircuits();
	
	//Create the package that contains the decommitments.
	DecommitmentsPackage provePack(select.size(), CryptoPrimitives::getHash()->getHashedMsgSize(),
		CryptoPrimitives::getAES()->getBlockSize(), execution->getCircuit(0)->getNumberOfInputs(1),
		CryptoPrimitives::getStatisticalParameter());
	int counter = 0;
	//Put in the decommitment package the decommitments of the seed, mask, and keys of each checked circuit and also the difference decommitments.
	for (auto j : select)
	{
		provePack.setIdDecommitment(counter, cmtSender->generateDecommitmentMsg(2 * j));// COMMIT_ID_SEED
		provePack.setMaskDecommitment(counter, cmtSender->generateDecommitmentMsg(2 * j + 1));// COMMIT_ID_COMMITMENT_MASK
		diffProtocol->getDecommit(j, counter, provePack);
		counter++;
	}
	//Send the decommitments to the cut and choose verifier.
	sendSerialize(provePack, commParty[0].get());
}

void CutAndChooseProver::proveCorrectnessOfPlacementMasks()
{
	assert(buckets != NULL);	
	auto size = buckets->size();
	// For each bucket, run the verify stage of the diff protocol (for eval circuits).
	for (size_t i = 0; i < size; i++)
	{
		auto bucket = buckets->getBucket(i);
		auto bucketSize = bucket->size();
		vector<shared_ptr<DifferenceCommitmentCommitterBundle>> commitBucket(bucketSize);
		for (size_t j = 0; j < bucketSize; j++)
		{
			commitBucket[j] = bucket->getBundleAt(j)->getDifferenceCommitmentBundle();
		}
		diffProtocol->proveDifferencesBetweenMasks(commitBucket);
	}
}

CutAndChooseProver::CutAndChooseProver(const shared_ptr<ExecutionParameters>& execution, vector<shared_ptr<CommParty>> & channels, vector<shared_ptr<BundleBuilder>> & bundleBuilders)
{
	this->execution = execution;
	commParty = channels;
	this->bundleBuilders = bundleBuilders;
	numCircuits = execution->getNumCircuits();
	//Create the commitment objects.
	cmtSender = make_shared<CmtSimpleHashCommitter>(commParty[0], CryptoPrimitives::getRandom(), CryptoPrimitives::getHash(), CryptoPrimitives::getHash()->getHashedMsgSize());
	cmtReceiver = make_shared<CmtSimpleHashReceiver>(commParty[0], CryptoPrimitives::getHash(), CryptoPrimitives::getHash()->getHashedMsgSize());
	circuitBundles = vector<shared_ptr<Bundle>>(numCircuits);

	// Bucket allocation.
	buckets = NULL;
	bucketMapping = NULL;
}

void CutAndChooseProver::run()
{
	//LogTimer timer("constructGarbledCircuitBundles");
	//Prepare the garbled circuit, commitment and other parameters needed by the protocol.
	constructGarbledCircuitBundles();
	//timer.stop();

	//timer.reset("receiveCommitmentToCutAndChoose");
	//Receive the commitments of the circuits selection and mapping.
	receiveCommitmentToCutAndChoose();
	//timer.stop();

	//timer.reset("sendCommitments");
	//Generate and send to the verifier the commitments needed by the protocol (on keys, masks, seed, etc).
	sendCommitments();
	//timer.stop();

	//timer.reset("receiveCutAndChooseChallenge");
	//Receive from the verifier the decommitment of the circuit selection and mapping.
	receiveCutAndChooseChallenge();
	//timer.stop();
	//timer.reset("proveCheckCircuits");
	//Prove the checked circuits by sending to the verifier the decommitments of the seeds, masks, keys of the checked circuits.
	proveCheckCircuits();
	//timer.stop();
	//timer.reset("putCircuitsInBuckets");
	//Put all evaluated circuits in buckets according to the received mapping.
	putCircuitsInBuckets();
	///timer.stop();
	//timer.reset("proveCorrectnessOfPlacementMasks");
	//Prove the placement masks by sending the decommitments of the diff protocol.
	proveCorrectnessOfPlacementMasks();
	//timer.stop();

}

shared_ptr<BucketBundleList> CutAndChooseProver::getBuckets()
{
	//In case the buckets were not created yet, create them.
	if (NULL == buckets) {
		putCircuitsInBuckets();
	}
	//Return the filled buckets.
	return buckets;
}
