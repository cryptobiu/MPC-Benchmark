#include "../../../include/OfflineOnline/specs/OnlineProtocolP1.hpp"

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
void OnlineProtocolP1::evaluateMainCircuit() {

	//The time measuring is commented out in order to save time. 
	//The user always can print them in case he wants to see the protocol process.

	//		LogTimer timer = new LogTimer("Receiving Y2");
	//Receive the input bits of p2 input wires.
	CircuitInput y2 = receiveY2();
	//	timer.stop();

	//This package will hold all the necessary things that should be sent to the other party.
	//This way, there will be one sending of a big message instead of many small messages. This saves time.
	EvaluationPackage mainPackage;

	//	timer.reset("sendCommitmentMasks");
	//Add to the evaluationPackage the commitment masks of every circuit in the bucket.
	sendCommitmentMasks(mainBucket, mainPackage);
	//	timer.stop();

	//	timer.reset("decommitY2InputKeys");
	//Add the decommitments of all Y2 inputs of every circuit in the bucket according to the given y2 input bits.
	decommitY2InputKeys(mainBucket, mainPackage, y2);
	//	timer.stop();

	//timer.reset("sendPlacementMasks");
	//Add
	sendPlacementMasks(mainBucket, mainPackage);
	//	timer.stop();

	//timer.reset("sendXInputKeys");
	//Add the decommitments of p1 inputs of every circuit in the bucket.
	sendXInputKeys(mainBucket, mainPackage);
	//	timer.stop();

	//	timer.reset("selectAndEncryptProof");
	try {
		selectAndXorProof(mainBucket, mainPackage);
	}
	catch (InvalidInputException e) {
		throw IllegalStateException(e.what());
	}
	//	timer.stop();
	//	timer.reset("sendPackage");

	//Send the evaluation package (contains all the protocol messages) to p2.
	//channel->writeWithSize(mainPackage.toString());
	sendSerialize(mainPackage, channel.get());
	//timer.stop();
}

/**
* Computes the cheating recovery circuits part.
*
* pseudo code:
* 1. Receive the requested input from p2
* 2. Send the commitment masks
* 3. Decommit on p2 input wires' keys
* 4. Send the xor of the placement mask with the input
* 5. Decommit on p1 input wires' keys
* 6. Decommit on both output wires' keys
* @throws IOException
*/
void OnlineProtocolP1::evaluateCheatingRecoveryCircuit() {
	//	LogTimer timer = new LogTimer("Receiving D2");
	CircuitInput d2 = receiveY2();
	//	timer.stop();

	//This package will hold all the necessary things that should be sent to the other party.
	//This way, there will be one sending of a big message instead of many small messages. This saves time.
	EvaluationPackage crPackage;

	//	timer.reset("sendCommitmentMasks");
	//Add to the evaluationPackage the commitment masks of every circuit in the bucket.
	sendCommitmentMasks(crBucket, crPackage);
	//	timer.stop();

	//timer.reset("decommitD2InputKeys");
	//Add the decommitments of all d2 inputs of every circuit in the bucket according to the given d2 input bits.
	decommitD2InputKeys(crBucket, crPackage, d2);
	//	timer.stop();

	//	timer.reset("sendPlacementMasks");
	sendPlacementMasks(crBucket, crPackage);
	//	timer.stop();

	//	timer.reset("sendXInputKeys");
	//Add the decommitments of p1 inputs of every circuit in the bucket.
	sendXInputKeys(crBucket, crPackage);
	//	timer.stop();

	//	timer.reset("decommitOutputKeys");
	//Adds the decommitments of the output keys of every circuit in the bucket.
	decommitOutputKeys(mainBucket, crPackage);
	//	timer.stop();

	//	timer.reset("sendPackage");
	//Send the evaluation package (contains all the protocol messages) to p2.
	sendSerialize(crPackage, channel.get());
	//	timer.stop();
}

/**
* Receive the input bit of p2 input wires.
* @return the received bits.
* @throws IOException IN case of problem during the receiving.
*/
CircuitInput OnlineProtocolP1::receiveY2() {
	//Receive y2 from the other side as a byte array.
	vector<byte> y2;
	channel->readWithSizeIntoVector(y2);
	
	//Convert the bytes to a circuit input and return it.
	return CircuitInput(make_shared<vector<byte>>(y2));
}

/**
* Adds to the evaluationPackage the commitment masks of every circuit in the bucket.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
*/
void OnlineProtocolP1::sendCommitmentMasks(BucketBundle & bucket, EvaluationPackage & evaluationPackage) {
	//Create space to all commitment masks.
	auto size = CryptoPrimitives::getAES()->getBlockSize();
	vector<byte> commitmentMask(size*bucket.size());

	//Add the commitment mask of every circuit in the bucket to the array.
	auto bucketSize = bucket.size();
	for (size_t j = 0; j < bucketSize; j++) {
		memcpy(commitmentMask.data() + j*size, bucket.getBundleAt(j)->getCommitmentMask()->data(), size);
	}

	//add all masks to the evaluation package.
	evaluationPackage.setCommitmentMask(commitmentMask);
}

/**
* Adds the decommitments of all Y2 inputs of every circuit in the bucket according to the given y2 input bits.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
* @param y2 Input bit for each p2 input wire.
*/
void OnlineProtocolP1::decommitY2InputKeys(BucketBundle & bucket, EvaluationPackage & evaluationPackage, CircuitInput & y2) {

	//Sending the decommitments will not be done by sending the decommitments object since this is not efficient.
	//Instead, the values in the decommitments are copied to a one - dimension array and sent that way.

	//Create space to all decommitment.
	int size = bucket.getBundleAt(0)->getInputLabelsY2Size();
	int keySize = CryptoPrimitives::getAES()->getBlockSize();
	int hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();
	vector<byte> allDecommitmentsX(bucket.size() * size * keySize);
	vector<byte> allDecommitmentsR(bucket.size() * size * hashSize);

	//For every circuit in the bucket,
	auto bucketSize = bucket.size();
	for (size_t j = 0; j < bucketSize; j++) {
		auto commitmentBundleY2 = bucket.getBundleAt(j)->getCommitmentsY2();
		auto x = commitmentBundleY2->getDecommitmentsX();
		auto r = commitmentBundleY2->getDecommitmentsRandoms();
		//For each input wire, 
		for (int i = 0; i < size; i++) {
			//Get the decommitment values (x and r) and copy then to the created array. 
			memcpy(allDecommitmentsX.data() + keySize * (j * size + i), x->data() + (i * 2 + y2.getNthBit(i)) * keySize, keySize);
			memcpy(allDecommitmentsR.data() + hashSize * (j * size + i), r->data() + (i * 2 + y2.getNthBit(i)) * hashSize, hashSize);
		}
	}

	//Set the arrays to the evaluation package.
	evaluationPackage.setDecommitmentsToY2InputKeys(allDecommitmentsX, allDecommitmentsR);
}

/**
* Adds the decommitments of all D2 inputs of every circuit in the bucket according to the given d2 input bits.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
* @param d2 Input bit for each p2 input wire.
*/
void OnlineProtocolP1::decommitD2InputKeys(BucketBundle & bucket, EvaluationPackage & evaluationPackage, CircuitInput & d2) {
	// Since the real placement of the master key must be fixed when synthesizing the input keys
	// we cannot send the completion to D, but to D' (which is the master proof of cheating).
	// so D ^ D' = M, where M is the mask that we need to apply on d2.
	auto masterProofOfCheating = bucket.getBundleAt(0)->getSecret(); // M
	SecretKey maskOnD2 = KeyUtils::xorKeys(&masterProofOfCheating, &proofOfCheating); // D ^ M = D'
	
	auto maskOnD2Input = CircuitInput::fromSecretKey(maskOnD2);
	CircuitInput modifiedD2(make_shared<vector<byte>>(CircuitInput::xorCircuits(&d2, maskOnD2Input.get())));

	// This may reveal M, but in order to obtain M in future executions P2 must still know D (changes every execution).
	evaluationPackage.addMaskOnD2(*maskOnD2Input->getInputVectorShared());

	// reveal the input keys for d2 ^ D' 
	// if d2 = d1 ^ D:
	// d1 ^ d2 ^ D' = d1 ^ d1 ^ D ^ D ^ M = M
	decommitY2InputKeys(bucket, evaluationPackage, modifiedD2);
}

/**
* Adds to the evaluationPackage the placement masks of every circuit in the bucket.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
*/
void OnlineProtocolP1::sendPlacementMasks(BucketBundle & bucket, EvaluationPackage & evaluationPackage) {
	//Create space to all placement masks.
	auto x = *input->getInputVectorShared(); // x
	vector<byte> placementMask(bucket.size()*x.size());

	//Add the xor of the placement masks with the input of every circuit in the bucket to the array.
	auto bucketSize = bucket.size();
	for (size_t j = 0; j < bucketSize; j++) {
		auto mask = *bucket.getBundleAt(j)->getPlacementMask(); // m_j
		vector<byte> masked(x.size());

		auto xSize = x.size();
		for (size_t i = 0; i < xSize; i++) {
			masked[i] = x[i] ^ mask[i];
		}
		maskedX[j] = masked;
		memcpy(placementMask.data() + j*x.size(), masked.data(), x.size());
	}

	//Set the array to the evaluation package.
	evaluationPackage.setPlacementMask(placementMask);
}

/**
* Adds the decommitments of p1 inputs of every circuit in the bucket.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
*/
void OnlineProtocolP1::sendXInputKeys(BucketBundle & bucket, EvaluationPackage & evaluationPackage) {

	//Sending the decommitments will not be done by sending the decommitments object since this is not efficient.
	//Instead, the values in the decommitments are copied to a one - dimension array and sent that way.

	//Create space to all decommitment.
	int size = bucket.getBundleAt(0)->getNumberOfInputLabelsX();

	int keySize = CryptoPrimitives::getAES()->getBlockSize();
	int hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();

	vector<byte> allDecommitmentsX(bucket.size() * size * keySize);
	vector<byte> allDecommitmentsR(bucket.size() * size * hashSize);

	//For every circuit in the bucket,
	auto bucketSize = bucket.size();
	for (size_t j = 0; j < bucketSize; j++) {
		auto commitments = bucket.getBundleAt(j)->getCommitmentsX();
		auto x = commitments->getDecommitmentsX();
		auto r = commitments->getDecommitmentsRandoms();
		//For every input wire,
		for (int i = 0; i < size; i++) {

			//Get the decommitment values (x and r) and copy then to the created array. 
			//auto decom = commitments->getDecommitment(i, maskedX[j][i]);
			memcpy(allDecommitmentsX.data() + keySize*(j*size + i), x->data() + (i * 2 + maskedX[j][i]) * keySize, keySize);
			memcpy(allDecommitmentsR.data() + hashSize*(j*size + i), r->data() + (i * 2 + maskedX[j][i]) * hashSize, hashSize);
		}
	}

	//Set the arrays to the evaluation package.
	evaluationPackage.setDecommitmentsToXInputKeys(allDecommitmentsX, allDecommitmentsR);
}

/**
* Xor each output wire with random values in order to encrypt the output keys.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
* @throws InvalidInputException
*/
void OnlineProtocolP1::selectAndXorProof(BucketBundle &  bucket, EvaluationPackage & evaluationPackage) {

	auto aes = CryptoPrimitives::getAES();
	auto size = bucket.getBundleAt(0)->getNumberOfOutputLabels();

	vec_block_align r(size); // R[v]
	vec_block_align p(size); // plaintexts R[v] ^ D

	int keySize = aes->getBlockSize();
	auto bucketSize = bucket.size();

	vec_block_align xoredProof(size * bucket.size() * 2);
	block proof;
	memcpy(&proof, proofOfCheating.getEncoded().data(), SIZE_OF_BLOCK);

	//Xor the output keys with R[v] and P[v].
	for (int v = 0; v < size; v++) {
		auto key = aes->generateKey(KEY_SIZE).getEncoded();
		memcpy(&r[v], key.data(), SIZE_OF_BLOCK);
		//r[v] = _mm_loadu_si128((__m128i*)key.data());
		p[v] = _mm_xor_si128(r[v], proof);
		
		for (size_t j = 0; j < bucketSize; j++) {

			xoredProof[(v*bucketSize * 2 + j * 2)] = _mm_xor_si128(bucket.getBundleAt(j)->getOutputWiresAt(v * 2), r[v]);
			xoredProof[(v*bucketSize * 2 + j * 2 + 1)] = _mm_xor_si128(bucket.getBundleAt(j)->getOutputWiresAt(v * 2 + 1), p[v]);	
		}
	}

	//Set the xor result in the package to send to p2.
	vector<byte> xoredProofBytes;
	makeByteVectorFromBlockVector(xoredProof, xoredProofBytes);
	evaluationPackage.setXoredProofOfCheating(xoredProofBytes);

	// Send H(D)
	SecretKey hashedProof = KeyUtils::hashKey(&proofOfCheating, CryptoPrimitives::getHash().get(), CryptoPrimitives::getHKDF().get(), aes->getBlockSize());
	auto tmp = hashedProof.getEncoded();
	evaluationPackage.setHashedProofOfCheating(tmp);

}

/**
* Adds the decommitments of the output keys of every circuit in the bucket.
* @param bucket The bucket to use in the protocol.
* @param evaluationPackage The message that will be sent to p2.
*/
void OnlineProtocolP1::decommitOutputKeys(BucketBundle & bucket, EvaluationPackage & evaluationPackage) {
	// Reveal D.
	evaluationPackage.addProofOfCheating(proofOfCheating.getEncoded());
	int outputSize = bucket.getBundleAt(0)->getNumberOfOutputLabels();

	//Sending the decommitments will not be done by sending the decommitments object since this is not efficient.
	//Instead, the values in the decommitments are copied to a one - dimension array and sent that way.

	//Create space to all decommitment.
	int keySize = CryptoPrimitives::getAES()->getBlockSize();
	int hashSize = CryptoPrimitives::getHash()->getHashedMsgSize();

	vector<byte> allDecommitmentsX(bucket.size() * keySize * outputSize * 2);
	vector<byte> allDecommitmentsR(bucket.size() * hashSize);

	// For each circuit in the bucket, get the decommitment and put it in the package.
	auto bucketSize = bucket.size();
	for (size_t j = 0; j < bucketSize; j++) {
		auto outputDecommitments = bucket.getBundleAt(j)->getDecommitmentsOutputKeys();

		vector<byte> x = *(vector<byte>*)(outputDecommitments->getX().get());
		vector<byte> r = dynamic_pointer_cast<ByteArrayRandomValue>(outputDecommitments->getR())->getR();

		memcpy(allDecommitmentsX.data() + keySize*outputSize * 2 * j, x.data(), keySize * outputSize * 2);
		memcpy(allDecommitmentsR.data() + hashSize*j, r.data(), hashSize);
	}

	//Set the arrays to the evaluation package.
	evaluationPackage.setDecommitmentsToOutputKeys(allDecommitmentsX, allDecommitmentsR);
}

/**
* A constructor that sets the given parameters and initializes some inline members.
* @param mainExecution Contains some parameters regarding the execution of the main circuits.
* @param crExecution Contains some parameters regarding the execution of the cheating recovery circuits.
* @param primitives Contains some primitives object to use during the protocol.
* @param mainBucket Contain the main circuits (for ex. AES).
* @param crBucket Contain the cheating recovery circuits.
*/
OnlineProtocolP1::OnlineProtocolP1(int argc, char* argv[]) : Protocol ("OnlineMaliciousYao", argc, argv){

    const string HOME_DIR = "../..";
    shared_ptr<CommunicationConfig> commConfig(new CommunicationConfig(HOME_DIR + arguments["partiesFile"], 1, io_service));
    auto commParty = commConfig->getCommParty();

    cout << "\nP1 start communication\n";

    //make connection
    for (int i = 0; i < commParty.size(); i++)
        commParty[i]->join(500, 5000);

    this->channel = commParty[0];
	maskedX.resize(mainBucket.size() > crBucket.size() ? mainBucket.size() : crBucket.size());
	vector<byte> proof;
	CryptoPrimitives::getPrg()->getPRGBytes(proof, 0, SIZE_OF_BLOCK); // D
	SecretKey tmp(proof, "");
	proofOfCheating = tmp;
}

void OnlineProtocolP1::setBuckets(BucketBundle & mainBucket, BucketBundle & crBucket){
    this->mainBucket = mainBucket;
    this->crBucket = crBucket;
    maskedX.resize(mainBucket.size() > crBucket.size() ? mainBucket.size() : crBucket.size());
    vector<byte> proof;
    CryptoPrimitives::getPrg()->getPRGBytes(proof, 0, SIZE_OF_BLOCK); // D
    SecretKey tmp(proof, "");
    proofOfCheating = tmp;
}

/**
* Executes the first side of the online protocol.<p>
* basically, it computes the main circuit and than the cheating recovery circuit.
*/
void OnlineProtocolP1::runOnline() {
	//	LogTimer timer = new LogTimer("Evaluating Main circuit");

	//Compute the main circuits part.
	evaluateMainCircuit();
	//	timer.stop();

	//	timer.reset("Evaluating CR circuit");
	//Compute the cheating recovery circuits part.
	evaluateCheatingRecoveryCircuit();
	//	timer.stop();
}