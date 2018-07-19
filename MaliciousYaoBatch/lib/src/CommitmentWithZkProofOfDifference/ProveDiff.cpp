#include "../../include/CommitmentWithZkProofOfDifference/ProveDiff.hpp"

ProveDiff::ProveDiff(int numCircuits, size_t n, int s)
{
	this->n = n;
	this->s = s;
}

vector<byte> ProveDiff::getCommittedDifference(size_t i)
{
	//Create an array and copy the necessary bytes into the created array.
	vector<byte> ret(committedDifference.begin() + i * n, committedDifference.begin() + (i+1) * n);
	return ret;
}

void ProveDiff::setCommittedDifference(size_t i, vector<byte> & committedDifferenceNew)
{
	//Copy the given value to the big class member.
	committedDifference.insert(committedDifference.begin() + i * n, committedDifferenceNew.begin(), committedDifferenceNew.end());
}

vector<byte> ProveDiff::getDelta(size_t i)
{
	//Create an array and copy the necessary bytes into the created array.
	vector<byte> ret(delta.begin() + i * 2 * s*n, delta.begin() + (i+1) * 2 * s*n);
	return ret;
}

void ProveDiff::setDelta(size_t i, vector<byte> & deltaNew)
{
	// Copy the given value to the big class member.
	delta.insert(delta.begin() + i * 2 * s * n, deltaNew.begin(), deltaNew.end());
}

/**
* Returns the committed difference from the given index in the committedDifference class member.
* @param i The index of the committed difference to return.
*/
vector<shared_ptr<CmtCDecommitmentMessage>> ProveDecommitments::getDecommitments() {
	int size = decommitmentsX.size() / xSize;
	vector<shared_ptr<CmtCDecommitmentMessage>> ret(size);
	for (int i = 0; i < size; i++) {
		vector<byte> r(decommitmentsR.begin() + i*rSize, decommitmentsR.begin() + (i + 1)*rSize);
		vector<byte> x(decommitmentsX.begin() + i*xSize, decommitmentsX.begin() + (i + 1)*xSize);
		//Create and return a CmtCDecommitmentMessage from the copied x, r.
		ret[i] = make_shared<CmtSimpleHashDecommitmentMessage>(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
	}

	return ret;
}

/**
* Sets the given committed difference in the given index in the committedDifference inline member.
* @param i The index where to put the given committedDifference.
* @param committedDifference The value to put.
*/
ProveDecommitments::ProveDecommitments(vector<byte> & decommitmentsX, int xSize, vector<byte> & decommitmentsR, int rSize){

	this->xSize = xSize;
	this->rSize = rSize;

	this->decommitmentsX = decommitmentsX;
	this->decommitmentsR = decommitmentsR;
	
}

