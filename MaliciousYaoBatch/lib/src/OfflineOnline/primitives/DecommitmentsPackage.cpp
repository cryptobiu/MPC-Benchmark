#include "../../../include/OfflineOnline/primitives/DecommitmentsPackage.hpp"

DecommitmentsPackage::DecommitmentsPackage(size_t numCircuits, int hashSize, int keySize, int inputSize, int s)
{
	this->hashSize = hashSize;
	this->keySize = keySize;
	this->inputSize = inputSize;
	this->s = s;

	idCommitmentsX.resize(numCircuits*hashSize);
	idCommitmentsR.resize(numCircuits*hashSize);
	maskCommitmentsX.resize(numCircuits*keySize);
	maskCommitmentsR.resize(numCircuits*hashSize);
	x.resize(numCircuits*inputSize);
	r.resize(numCircuits*inputSize*s);
	diffDecommitmentsX.resize(numCircuits * 2 * s*inputSize);
	diffDecommitmentsR.resize(numCircuits * 2 * s*inputSize);
}

shared_ptr<CmtCDecommitmentMessage> DecommitmentsPackage::getMaskDecommitment(int i)
{
	//Copy the matching r and x of the requested mask decommitment.
	vector<byte> r(maskCommitmentsR.begin() + i*hashSize, maskCommitmentsR.begin() + (i + 1)*hashSize);
	vector<byte> x(maskCommitmentsX.begin() + i*keySize, maskCommitmentsX.begin() + (i + 1)*keySize);

	//Create and return a CmtCDecommitmentMessage from the copied x, r.
	return make_shared<CmtSimpleHashDecommitmentMessage>(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}

void DecommitmentsPackage::setMaskDecommitment(int i, shared_ptr<CmtCDecommitmentMessage> maskCommitments)
{
	//Copy the decommitment's values to the class members.
	auto maskX = static_pointer_cast<vector<byte>>(maskCommitments->getX());
	maskCommitmentsX.insert(maskCommitmentsX.begin() + i*keySize, maskX->begin(), maskX->end());
	auto maskR = static_pointer_cast<ByteArrayRandomValue>(maskCommitments->getR())->getR();
	maskCommitmentsR.insert(maskCommitmentsR.begin() + i*hashSize, maskR.begin(), maskR.end());
}

shared_ptr<CmtCDecommitmentMessage> DecommitmentsPackage::getIdDecommitment(int i)
{
	//Copy the matching r and x of the requested id decommitment.
	vector<byte> r(idCommitmentsR.begin() + i*hashSize, idCommitmentsR.begin() + (i + 1)*hashSize);
	vector<byte> x(idCommitmentsX.begin() + i*hashSize, idCommitmentsX.begin() + (i + 1)*hashSize);

	//Create and return a CmtCDecommitmentMessage from the copied x, r.
	return make_shared<CmtSimpleHashDecommitmentMessage>(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}

void DecommitmentsPackage::setIdDecommitment(int i, shared_ptr<CmtCDecommitmentMessage> idCommitments)
{
	//Copy the decommitment's values to the class members.
	auto x = static_pointer_cast<vector<byte>>(idCommitments->getX());
	idCommitmentsX.insert(idCommitmentsX.begin() + i*hashSize, x->begin(), x->end());
	auto r = static_pointer_cast<ByteArrayRandomValue>(idCommitments->getR())->getR();
	idCommitmentsR.insert(idCommitmentsR.begin() + i*hashSize, r.begin(), r.end());
}

void DecommitmentsPackage::setX(int k, shared_ptr<vector<byte>> newX)
{
	memcpy(x.data() + k*inputSize, newX->data(), inputSize);
}

shared_ptr<vector<byte>> DecommitmentsPackage::getX(int i)
{
	//Copy the requested value and return it.
	return make_shared<vector<byte>>((this->x).begin() + i*inputSize, (this->x).begin() + (i + 1)*inputSize);
}

void DecommitmentsPackage::setR(int k, vector<byte> & newR)
{
	memcpy(r.data() + k*inputSize*s, newR.data(), inputSize*s);
}

shared_ptr<vector<byte>> DecommitmentsPackage::getR(int k)
{
	//Copy the requested value and return it.
	return make_shared<vector<byte>>((this->r).begin() + k*inputSize*s, (this->r).begin() + (k+1)*inputSize*s);
}

vector<vector<byte>> DecommitmentsPackage::getDiffDecommitmentX(int i, int size)
{
	//Allocate a new array in the given size.
	vector<vector<byte>> decommitments(size);
	//Copy each CmtCDecommitmentMessage to its place.
	for (int k = 0; k<size; k++) {
		decommitments[k].resize(inputSize);
		memcpy(decommitments[k].data(), diffDecommitmentsX.data() + i * 2 * s*inputSize + k*inputSize, inputSize);
	}
	//Return the created array.
	return decommitments;
}

vector<vector<byte>> DecommitmentsPackage::getDiffDecommitmentR(int i, int size)
{
	//Allocate a new array in the given size.
	vector<vector<byte>> decommitments(size);
	//Copy each CmtCDecommitmentMessage to its place.
	for (int k = 0; k<size; k++) {
		decommitments[k].resize(hashSize);
		memcpy(decommitments[k].data(), diffDecommitmentsR.data() + i * 2 * s*hashSize + k*hashSize, hashSize);
	}
	//Return the created array.
	return decommitments;
}

void DecommitmentsPackage::setDiffDecommitments(int i, vector<vector<byte>>& decommitmentsX, vector<vector<byte>>& decommitmentsR)
{
	//Copy each CmtCDecommitmentMessage to its place in the class member.
	int len = decommitmentsX.size();
	for (int k = 0; k<len; k++) {
		memcpy(diffDecommitmentsX.data() + i * 2 * s*inputSize + k*inputSize, decommitmentsX[k].data(), inputSize);
		memcpy(diffDecommitmentsR.data() + i * 2 * s*hashSize + k*hashSize, decommitmentsR[k].data(), hashSize);
	}
	
}