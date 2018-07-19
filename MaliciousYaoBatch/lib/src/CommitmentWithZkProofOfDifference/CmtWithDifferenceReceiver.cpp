#include "../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceReceiver.hpp"

CmtWithDifferenceReceiver::CmtWithDifferenceReceiver(shared_ptr<CutAndChooseSelection> selection, int numCircuits, 
	int statisticalParameter, const shared_ptr<CommParty> & channel, const shared_ptr<CryptographicHash> & hash) :
	CmtWithDifferenceParty(numCircuits, statisticalParameter, channel)
{
	this->selection = selection;
	this->c = vector<vector<vector<byte>>>(numCircuits);
	this->receivedDeltas = vector<shared_ptr<vector<byte>>>(numCircuits * 2 * s);

	//Initialize the commitment scheme.
	initCommitmentScheme(channel, hash);

	//Select the sigma array and key for the encryption scheme.
	//Generate a key for the encryption scheme and set it.
	k = enc->generateKey(128);
	enc->setKey(k);
	//Select the sigma array.
	w.resize(s);
	makeRandomBitByteVector(CryptoPrimitives::getRandom().get(), w);
}

void CmtWithDifferenceReceiver::setup()
{
	//Generate CmtCCommitmentMsg from w and k.
	shared_ptr<CmtCCommitmentMsg> comW = cmtSender->generateCommitmentMsg(cmtSender->generateCommitValue(w), COMMIT_LABEL_W);
	auto tempKEncoded = k.getEncoded();
	shared_ptr<CmtCCommitmentMsg> comK = cmtSender->generateCommitmentMsg(cmtSender->generateCommitValue(tempKEncoded), COMMIT_LABEL_K);

	//Generate decommit values for w and k.
	decomW = cmtSender->generateDecommitmentMsg(COMMIT_LABEL_W);
	decomK = cmtSender->generateDecommitmentMsg(COMMIT_LABEL_K);

	// Commit to W (cmtSelection) and K (the key for the symmetric enc).
	//sendSerialize(comW, channel);
	channel->writeWithSize(comW->toString());
	//sendSerialize(std::static_pointer_cast<CmtSimpleHashCommitmentMessage>(comK), channel);
	sendSerialize(comK, channel.get());

	// Send encrypted cut and choose selection.
	ByteArrayPlaintext plaintext(selection->asByteArray());
	auto temp = enc->encrypt(&plaintext);
	sendSerialize(temp, channel.get());
}

void CmtWithDifferenceReceiver::receiveCommitment(vector<vector<vector<byte>>> & commitments)
{
	c = commitments;
}

void CmtWithDifferenceReceiver::revealCutAndChooseSelection()
{
	// Decommit k so that the other party can decrypt ccSelection.
	sendSerialize(decomK, channel.get());
}

shared_ptr<vector<byte>> CmtWithDifferenceReceiver::receiveDecommitment(size_t index, int counter, DecommitmentsPackage & pack)
{
	// Receive the committed value from the package.
	auto x = pack.getX(counter);
	// Receive the random values used to commit (r_1, ..., r_s) from the package.
	auto r = pack.getR(counter);
	// Receive decommitment to c[k] from the package.
	auto decommitmentsX = pack.getDiffDecommitmentX(counter, 2 * s);
	auto decommitmentsR = pack.getDiffDecommitmentR(counter, 2 * s);

	size_t xSize = x->size();
	
	auto hash = CryptoPrimitives::getHash();
	int size = hash->getHashedMsgSize();

	vector<byte> result(size);
	//Verify each pair of decommitments. 
	//If verified, check that the committed values are indeed r and x^r.
	//Else, throw a cheating exception.
	for (int i = 0; i < s; i++)  // there are s pairs.
	{
		//Get r[i].
		auto start = &r->at(i*xSize);
		auto ri = vector<byte>(start, start + xSize);

		// Compute x ^ r[i].
		vector<byte> xXorRi(xSize);
		for (int j = 0; j < xSize; j++) {
			xXorRi[j] = (byte)(x->at(j) ^ ri[j]);
		}

		// Verify c_k in the i^th place against decom(i).
		//auto c0Val = cmtReceiver->verifyDecommitment(c[index][i * 2].get(), decommitments[i * 2].get());
		//auto c1Val = cmtReceiver->verifyDecommitment(c[index][i * 2 + 1].get(), decommitments[i * 2 + 1].get());
		verifyDecommitment(hash.get(), &c[index][i * 2], decommitmentsX[i * 2], decommitmentsR[i * 2], 0, size, result);
		verifyDecommitment(hash.get(), &c[index][i * 2 + 1], decommitmentsX[i * 2 + 1], decommitmentsR[i * 2 + 1], 0, size, result);

		//If verified, convert the committed value to a string.
		auto xXorRiDecom = decommitmentsX[i * 2];
		auto riDecom = decommitmentsX[i * 2 + 1];

		//Check that the committed value are indeed r and x^r.
		//If not, throw an exception.
		if ((xXorRiDecom != xXorRi) || (riDecom !=ri))
		{
			throw CheatAttemptException("decommitment failed!");
		}
	}

	return x;
}

DifferenceCommitmentReceiverBundle CmtWithDifferenceReceiver::getBundle(int j)
{
	return DifferenceCommitmentReceiverBundle(make_shared<vector<byte>>(w), decomW, c[j]);
}

vector<shared_ptr<vector<byte>>> CmtWithDifferenceReceiver::verifyDifferencesBetweenMasks(vector<shared_ptr<DifferenceCommitmentReceiverBundle>>& bucket)
{
	vector<shared_ptr<vector<byte>>> committedDifference(bucket.size());

	//Receive the message from the committer.
	ProveDiff msg;
	readSerialize(msg, channel.get());
	
	// Receive the committed difference for each secret.
	size_t sizeBucket = bucket.size();
	for (size_t j = 0; j < sizeBucket - 1; j++)
	{
		committedDifference[j] = receiveDifference(j, msg);
	}

	//Send w to the committer.
	decommitToW();

	ProveDecommitments package;
	readSerialize(package, channel.get());
	
	//Verify the received decommitments.
	for (size_t j = 0; j < sizeBucket - 1; j++)
	{
		verifyDifference(bucket[j], bucket[j+1], j, package);
	}

	//If all verified, return the committed differences.
	return committedDifference;
}

shared_ptr<vector<byte>> CmtWithDifferenceReceiver::receiveDifference(size_t index, ProveDiff & msg)
{
	//Extract the difference from the committer's package.
	auto committedDifference = make_shared<vector<byte>>(msg.getCommittedDifference(index));
	
	//Extract the delta from the committer's package (which is the xor of both committed values).
	auto delta = msg.getDelta(index);

	n = delta.size() / s / 2;

	//For each pair of commitments, calculate the difference using the delta.
	for (unsigned int i = 0; i < s; i++)
	{
		vector<byte> calculatedDifference(n);

		// CalculatedDifference = delta0[i] ^ delta1[i] = x ^ r_i ^ y ^ p_i ^ r_i ^ p_i = x ^ y.
		for (size_t j = 0; j < n; j++)
		{
			calculatedDifference[j] = (byte)(delta[2 * i*n + j] ^ delta[(2 * i + 1)*n + j]);
		}
		
		//Check that the calculated value is equal to the received value.
		//If not, throw a cheating exception.
		if (!equal(calculatedDifference.begin(), calculatedDifference.end(), committedDifference->begin()))
		{
			string temp = "d0_i ^ d1_i != delta for i = " + to_string(i) + " and k = " + to_string(index);
			throw CheatAttemptException(temp);
		}
	}

	//If all verified, save the delta and return the differences.
	receivedDeltas[index] = make_shared<vector<byte>>(delta);
	return committedDifference;
}

void CmtWithDifferenceReceiver::decommitToW()
{
	// decommit W (cmtSelection).
	//sendSerialize(decomW, channel);
	auto x = static_pointer_cast<vector<byte>>(decomW->getX());
	auto r = static_pointer_cast<ByteArrayRandomValue>(decomW->getR())->getR();
	channel->writeWithSize(r.data(), r.size());
	channel->writeWithSize(x->data(), x->size());
}

void CmtWithDifferenceReceiver::verifyDifference(shared_ptr<DifferenceCommitmentReceiverBundle>& b1, shared_ptr<DifferenceCommitmentReceiverBundle>& b2, size_t k1, ProveDecommitments & decommitments)
{
	//Get both commitments and delta.
	auto c1 = b1->getC();
	auto c2 = b2->getC();
	shared_ptr<vector<byte>> delta = receivedDeltas[k1];
	
	auto hash = CryptoPrimitives::getHash();
	int hashSize = hash->getHashedMsgSize();
	int keySize = decommitments.getXSize();
	auto decommitmentsX = decommitments.getDecommitmentsX();
	auto decommitmentsR = decommitments.getDecommitmentsR();

	vector<byte> tmp(hashSize);
	//Verify each pair of decommitments.
	//If verified, get both committed values and xor them.
	//Then, check that the xor is equal to the expected from the delta array.
	for (int i = 0; i < s; i++)
	{
		//Get the index of the decommitments according to w.
		int decomIndex = 2 * i + w[i]; // c0[i] if w[i] == 0 or c1[i] if w[i] == 1.
		
		//Verify the decommitments.
		vector<byte> cSigma(decommitmentsX.begin() + (k1 * 2 * s + 2 * i) * keySize, decommitmentsX.begin() + (k1 * 2 * s + 2 * i + 1) * keySize);
		vector<byte> dSigma(decommitmentsX.begin() + (k1 * 2 * s + 2 * i + 1) * keySize, decommitmentsX.begin() + (k1 * 2 * s + 2 * i + 2) * keySize);
		verifyDecommitment(hash.get(), &c1[decomIndex], cSigma, decommitmentsR, (k1 * 2 * s + 2 * i) * hashSize, hashSize, tmp);
		verifyDecommitment(hash.get(), &c2[decomIndex], dSigma, decommitmentsR, (k1 * 2 * s + 2 * i + 1) * hashSize, hashSize, tmp);

		size_t xorSize = cSigma.size();
		vector<byte> xorVec (xorSize);
		for (size_t j = 0; j < xorSize; j++) {
			xorVec[j] = (byte)(cSigma[j] ^ dSigma[j]);
		}

		//Get the expected xor.
		vector<byte> check(&delta->at(decomIndex*n), &delta->at(decomIndex*n) + n);

		//Check that the xor is equal to the expected.
		//If not, throw a cheating exception.
		if (!equal(check.begin(), check.end(), xorVec.begin()))
		{
			// Decom(c_i^{W_i}) xor Decom(c_i^{W_i}) != delta_i^{W_i}
			throw CheatAttemptException("Decom(c_i^{W_i}) xor Decom(c_i^{W_i}) != delta_i^{W_i}");
		}
	}
}

void CmtWithDifferenceReceiver::verifyDecommitment(CryptographicHash* hash, vector<byte>* commitment, vector<byte> & x, vector<byte> & r, int rOffset, int hashSize, vector<byte> & result) {
	
	//create an array that will hold the concatenation of r with x
	hash->update(r, rOffset, hashSize);
	hash->update(x, 0, x.size());
	hash->hashFinal(result, 0);

	//Checks that c = H(r,x)
	if (*commitment != result)
		throw CheatAttemptException("Failed to decommit difference!");
}
