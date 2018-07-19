#include "../../../include/OfflineOnline/primitives/Bundle.hpp"

Bundle::Bundle(const shared_ptr<vector<byte>> & seed, const shared_ptr<GarbledBooleanCircuit> & garbledCircuit, block * wireValues, int numberOfOutputs,
	const shared_ptr<vector<byte>> & placementMask, const shared_ptr<vector<byte>> & commitmentMask, int inputLabelsXSize,
	int labelsY2Size, vec_block_align & inputWiresY1Extended,
	const shared_ptr<CommitmentBundle> &  commitmentsX, const shared_ptr<CommitmentBundle> & commitmentsY1Extended,
	const shared_ptr<CommitmentBundle> & commitmentsY2, const shared_ptr<CmtCCommitmentMsg> & commitment, const shared_ptr<CmtCDecommitmentMessage> & decommit,
	SecretKey & secret, int keySize)
{
	this->seed = seed;

	this->garbledTableSize = garbledCircuit->getGarbledTableSize();
	garbledTables = (block *)_mm_malloc(garbledTableSize, SIZE_OF_BLOCK);
	memcpy((byte*)garbledTables, (byte*)garbledCircuit->getGarbledTables(), garbledTableSize);
	this->translationTable = garbledCircuit->getTranslationTable();

	this->placementMask =placementMask;
	this->commitmentMask = commitmentMask;

	this->inputLabelsXSize = inputLabelsXSize;
	this->labelsY2Size = labelsY2Size;

	this->inputWiresY1Extended = inputWiresY1Extended;
	this->numberOfOutputs = numberOfOutputs;
	this->outputWires = wireValues;

	this->commitmentsX = commitmentsX;
	this->commitmentsY1Extended = commitmentsY1Extended;
	this->commitmentsY2 = commitmentsY2;
	this->commitment = commitment;
	this->decommit = decommit;

	this->secret = secret;

	this->keySize = keySize;
}

block Bundle::getProbeResistantWire(size_t wireIndex, int sigma)
{
	//check binary
	assert((0 <= sigma) && (sigma <= 1));

	block output;
	memcpy(&output, (byte*)&inputWiresY1Extended[wireIndex * 2 + sigma], SIZE_OF_BLOCK);
	
	return output;
}

void Bundle::getCommitments(CommitmentsPackage & pack)
{
	pack.setCommitmentsX(commitmentsX->getCommitments(), &commitmentsX->getCommitmentsIds());
	pack.setCommitmentsY1Extended(commitmentsY1Extended->getCommitments(), &commitmentsY1Extended->getCommitmentsIds());
	pack.setCommitmentsY2(commitmentsY2->getCommitments(), &commitmentsY2->getCommitmentsIds());
	pack.setCommitmentsOutputKeys(commitment.get());
}

vector<byte> Bundle::getGarbleTableToSend()
{
	byte* temp = (byte*)garbledTables;
	
	return vector<byte>(temp, temp+ garbledTableSize);
}
