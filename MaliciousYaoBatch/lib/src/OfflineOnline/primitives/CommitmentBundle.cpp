#include "../../../include/OfflineOnline/primitives/CommitmentBundle.hpp"

CommitmentBundle::CommitmentBundle(const shared_ptr<vector<byte>> & commitmentsVec, vector<long>& commitmentsIdsVec, const shared_ptr<vector<byte>> & decommitmentsVec, const shared_ptr<vector<byte>> & decommitmentRandomsVec)
{
	this->commitments = commitmentsVec;
	this->commitmentIds = commitmentsIdsVec;
	this->decommitments = decommitmentsVec;
	this->decommitmentRandoms = decommitmentRandomsVec;
}

void CommitmentBundle::doConstruct(PrgFromOpenSSLAES* random, CryptographicHash* hash, int keyLength, vec_block_align& wires, size_t labelsSize, vector<byte>& commitmentMask,
	vector<byte>& placementMask) {
	
	commitmentSize = hash->getHashedMsgSize();
	int commitLabel = 0;
	keySize = 16;

	commitments = make_shared<vector<byte>>(labelsSize * 2 * commitmentSize);
	commitmentIds.resize(labelsSize * 2);
	decommitments = make_shared<vector<byte>>(labelsSize * 2 * keySize);
	decommitmentRandoms = make_shared<vector<byte>>(labelsSize * 2 * commitmentSize);

	block keys[2];
	block toComper, effectiveKey;
	vector<byte> toCommit(SIZE_OF_BLOCK);
	vector<byte> r(hash->getHashedMsgSize());

	// For each wire w (indexed with i)
	for (int i = 0; i < labelsSize; i++)
	{	
		keys[0] = wires[i * 2];
		keys[1] = wires[i * 2 + 1];
		
		// Switch the keys according to mask[j]
		if (!placementMask.empty() && placementMask[i] == 1)
		{
			block temp = keys[0];
			keys[0] = keys[1];
			keys[1] = temp;
		}

		memcpy(&toComper, commitmentMask.data(), commitmentMask.size());
		// Generate Com(K0), Com(K1), Decom(K0), Decom(K1) according to the ordering in B[j].
		//num of keys = 2;
		for (int k = 0; k < 2; k++)
		{
			effectiveKey = keys[k];
			if (!commitmentMask.empty())
			{
				effectiveKey = _mm_xor_si128(effectiveKey, toComper);
			}			
			toCommit.assign((byte*)&effectiveKey, (byte*)&effectiveKey + 16);
			
			calcCommitment(random, r, hash, toCommit, commitLabel, i, k);
			
			commitLabel++;
		}
	}
}

void CommitmentBundle::calcCommitment(PrgFromOpenSSLAES* prg, vector<byte> & r, CryptographicHash* hash, vector<byte> & value, long id, int i, int k) {
	
	//Sample random byte array r
	prg->getPRGBytes(r, 0, r.size());

	//Compute the hash function
	hash->update(r, 0, r.size());
	hash->update(value, 0, value.size());
	hash->hashFinal(*commitments, i * 2 * commitmentSize + k*commitmentSize);

	commitmentIds[i * 2 + k] = id;
	memcpy(&decommitments->at(i * 2 * keySize + k*keySize), &value[0], keySize);
	memcpy(&decommitmentRandoms->at(i * 2 * commitmentSize + k*commitmentSize), &r[0], commitmentSize);

}

CmtSimpleHashCommitmentMessage CommitmentBundle::getCommitment(size_t wireIndex, int sigma) const
{
	//check binary
	assert((0 <= sigma) && (sigma <= 1));

	//Return the commitment that matches the given sigma of the given wire index.
	auto commitment = make_shared<vector<byte>>(this->commitmentSize);
	memcpy(&commitment->at(0), &commitments->at(wireIndex * 2 * commitmentSize + sigma*commitmentSize), commitmentSize);
	return CmtSimpleHashCommitmentMessage(commitment, commitmentIds[wireIndex * 2 + sigma]);
}

CmtSimpleHashDecommitmentMessage CommitmentBundle::getDecommitment(size_t wireIndex, int sigma)
{
	//check binary
	assert((0 <= sigma) && (sigma <= 1));

	//Return the decommitment that matches the given sigma of the given wire index.
	auto start = &decommitmentRandoms->at(wireIndex * 2 * commitmentSize + sigma*commitmentSize);
	auto r = vector<byte>(start, start + this->commitmentSize);

	start = &decommitments->at(wireIndex * 2 * keySize + sigma*keySize);
	auto x = vector<byte>(start, start + this->keySize);

	//TODO - make sure make_shared<vector<byte>>(x) make copy of x
	return CmtSimpleHashDecommitmentMessage(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}

bool CommitmentBundle::operator==(const CommitmentBundle & b)
{
	int size = commitmentIds.size() / 2;
	//For each wire's index in the labels array:
	for (int i = 0; i < size; i++) {
		//Get the index and the matching commitments.
		//Check that both commitments are equal.
		for (int k = 0; k < 2; k++) {
			auto m1 = this->getCommitment(i, k);
			auto m2 = b.getCommitment(i, k);
			
			auto c1 = m1.getCommitmentArray();
			auto c2 = m2.getCommitmentArray();
			if ((m1.getId() != m2.getId()) || (*c1 != *c2)) {
				boost::format formatter("commitments differ for index=%1% and sigma=%2%: c1 = %3%, c2 = %4%");
				formatter % i;
				formatter % k;
				formatter % c1;
				formatter % c2;
				throw CheatAttemptException(formatter.str());
				return false;
			}
		}
	}
	return true;
}
