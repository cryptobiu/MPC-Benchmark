#include "../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceCommitter.hpp"

void CmtWithDifferenceCommitter::commitToDifference(DifferenceCommitmentCommitterBundle & b1, DifferenceCommitmentCommitterBundle & b2, size_t index, ProveDiff & msg)
{
	auto x1 = b1.getX();
	auto x2 = b2.getX();
	auto c1 = b1.getC();
	auto c2 = b2.getC();

	// Send the difference x[k1] ^ x[k2] (but not the masks themselves).
	vector<byte> committedDifference(n);
	for (size_t j = 0; j < n; j++)
	{
		committedDifference[j] = (byte)(x1->at(j) ^ x2->at(j));
	}
	msg.setCommittedDifference(index, committedDifference);
	// P1 sends 2*s shares to P2.
	// P2 must choose a challenge W (the choose).
	//P1 sends the xor of both committed values. 
	vector<byte> delta(2 * s*n);
	for (int i = 0; i < s; i++)
	{
		// Xor loop.
		for (size_t j = 0; j < n; j++)
		{
			auto c1R = c1->getR(i)->at(j);
			auto c2R = c2->getR(i)->at(j);
			delta[2 * i*n + j] = (byte)(x1->at(j) ^ c1R ^ x2->at(j) ^ c2R); // x ^ r_i ^ y ^ p_i
			delta[(2 * i + 1)*n + j] = (byte)(c1R ^ c2R); // r_i ^ p_i
		}
	}

	msg.setDelta(index, delta);
}

void CmtWithDifferenceCommitter::receiveW()
{
	//read CmtCDecommitmentMessage
	//shared_ptr<CmtCDecommitmentMessage> wDecommitment;
	//readSerialize(wDecommitment, channel);
	vector<byte> random, x;
	channel->readWithSizeIntoVector(random);
	channel->readWithSizeIntoVector(x);
	auto wDecommitment = make_shared<CmtSimpleHashDecommitmentMessage>(make_shared<ByteArrayRandomValue>(random), make_shared<vector<byte>>(x));

	//Verify w.
	shared_ptr<CmtCommitValue> wVal = cmtReceiver->verifyDecommitment(wCommitment.get(), wDecommitment.get());
	w = cmtReceiver->generateBytesFromCommitValue(wVal.get());
}

void CmtWithDifferenceCommitter::proveDifference(DifferenceCommitmentCommitterBundle & b1, DifferenceCommitmentCommitterBundle & b2, vector<byte> & decommitmentsX, vector<byte> & decommitmentsR, size_t index)
{
	int keySize = b1.getC()->getDecomX(0, w[0]).size();
	int hashSize = b1.getC()->getDecomR(0, w[0]).size();
	assert(this->w.size() != 0);
	//Get both decommitments of each pair.
	for (int i = 0; i < s; i++)
	{
		memcpy(decommitmentsX.data() + keySize*(2 * s*index + 2 * i), b1.getC()->getDecomX(i, w[i]).data(), keySize);
		memcpy(decommitmentsX.data() + keySize*(2 * s*index + 2 * i + 1), b2.getC()->getDecomX(i, w[i]).data(), keySize);
		memcpy(decommitmentsR.data() + hashSize*(2 * s*index + 2 * i), b1.getC()->getDecomR(i, w[i]).data(), hashSize);
		memcpy(decommitmentsR.data() + hashSize*(2 * s*index + 2 * i + 1), b2.getC()->getDecomR(i, w[i]).data(), hashSize);
	}
}

CmtWithDifferenceCommitter::CmtWithDifferenceCommitter(vector<shared_ptr<vector<byte>>>& x, int numCircuits, int statisticalParameter,
	shared_ptr<CommParty> channel, shared_ptr<CryptographicHash> hash) : CmtWithDifferenceParty(numCircuits, statisticalParameter, channel)
{
	//Initialize the commitment scheme.
	initCommitmentScheme(channel, hash);

	this->n = x[0]->size();

	//Check the lengths of the secrets.
	size_t size = x.size();
	for (size_t i = 0; i < size; i++) {
		if (x[i]->size() != n) {
			throw IllegalStateException("all secrets must be of the same length!");
		}
	}

	this->x = x;
	this->c = vector<shared_ptr<SC>>(numCircuits);
}

void CmtWithDifferenceCommitter::setup()
{
	//Receive wCommitment and kCommitment.
	//readSerialize(wCommitment, channel);
	vector<byte> tmp;
	channel->readWithSizeIntoVector(tmp);
	wCommitment = make_shared<CmtSimpleHashCommitmentMessage>();
	wCommitment->initFromByteVector(tmp);
	readSerialize(kCommitment, channel.get());

	//Receive the cutAndChooseSelectionCiphertext.
	readSerialize(cutAndChooseSelectionCiphertext, channel.get());
}

vector<vector<vector<byte>>> CmtWithDifferenceCommitter::getCommitments()
{
	vector<vector<vector<byte>>> commitments(numCircuits);
	auto prg = CryptoPrimitives::getRandom().get();
	//For each secret, create a SC object that generate the commitment pairs  and put the commitment in the above array.
	for (int i = 0; i < numCircuits; i++)
	{
		c[i] = make_shared<SC>( SC(prg, *x[i], commitmentId, s));
		commitmentId = c[i]->getNextAvailableCommitmentId();
		commitments[i] = c[i]->getCommitments();
	}

	return commitments;
}

/*CutAndChooseSelection CmtWithDifferenceCommitter::receiveCutAndChooseSelection()
{
	//read CmtCDecommitmentMessage via channel
	shared_ptr<CmtCDecommitmentMessage> kDecommitment;
	readSerialize(kDecommitment, channel);


	//Verify the kDecommitment.
	shared_ptr<CmtCommitValue> kVal = cmtReceiver->verifyDecommitment(&*kCommitment, &*kDecommitment);

	//If was not verified, throw a cheating exception.
	if (kVal == NULL) {
		throw new CheatAttemptException("decommitment of k failed!");
	}

	//Else, convert the committed value to a key to the encryption scheme.
	auto kBytes = cmtReceiver->generateBytesFromCommitValue(&*kVal);
	k = SecretKey(kBytes, "");
	try {
		//TODO - enc.setKey(k);
	}
	catch (InvalidKeyException e) {
		throw new CheatAttemptException(e.what());
	}

	//Decrypt the cut and choose selection and return it.
	//TODO - ByteArrayPlaintext selectionArray = (ByteArrayPlaintext)enc.decrypt(cutAndChooseSelectionCiphertext);
	return CutAndChooseSelection(selectionArray.getText());
}*/

void CmtWithDifferenceCommitter::getDecommit(int index, int counter, DecommitmentsPackage & pack)
{
	// Put x_k in the package.
	pack.setX(counter, this->x[index]);

	// Put all randoms r_1, ..., r_s in the package.
	auto temp = c[index]->getR();
	pack.setR(counter, temp);

	// Put decommitments to c[k] in the package.
	auto decommitmentsX = this->c[index]->getDecommitmentsX();
	auto decommitmentsR = this->c[index]->getDecommitmentsR();
	pack.setDiffDecommitments(counter, decommitmentsX, decommitmentsR);
}

shared_ptr<DifferenceCommitmentCommitterBundle> CmtWithDifferenceCommitter::getBundle(size_t index)
{
	//Create a bundle with the secret, its pairs of commitments and the wCommitment.
	return make_shared<DifferenceCommitmentCommitterBundle>(x[index], c[index], wCommitment);
}

void CmtWithDifferenceCommitter::proveDifferencesBetweenMasks(vector<shared_ptr<DifferenceCommitmentCommitterBundle>>& bucket)
{
	//Commit on each pair of bundles.
	size_t bucketSize = bucket.size();
	ProveDiff msg(bucketSize - 1, n, s);
	for (size_t j = 0; j <bucketSize - 1; j++)
	{
		commitToDifference(*bucket[j], *bucket[j+1], j, msg);
	}

	//Send the commitments to the other party.
	sendSerialize(msg, channel.get());
	
	//receive w.
	receiveW();

	//Send the decommitments of the committed differences.
	int xSize = bucket[0]->getC()->getDecomX(0, w[0]).size();
	vector<byte> decommitmentsX((bucket.size() - 1)*s * 2 * xSize);
	vector<byte> decommitmentsR((bucket.size() - 1)*s * 2 * CryptoPrimitives::getHash()->getHashedMsgSize());
	for (size_t j = 0; j < bucketSize - 1; j++)
	{
		proveDifference(*bucket[j], *bucket[j+1], decommitmentsX, decommitmentsR, j);
	}
	ProveDecommitments package(decommitmentsX, xSize, decommitmentsR, CryptoPrimitives::getHash()->getHashedMsgSize());
	sendSerialize(package, channel.get());
}
