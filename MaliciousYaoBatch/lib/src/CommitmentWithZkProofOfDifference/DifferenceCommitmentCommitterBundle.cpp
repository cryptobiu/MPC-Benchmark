#include "../../include/CommitmentWithZkProofOfDifference/DifferenceCommitmentCommitterBundle.hpp"

DifferenceCommitmentCommitterBundle::DifferenceCommitmentCommitterBundle(shared_ptr<vector<byte>> x, shared_ptr<SC> c, shared_ptr<CmtCCommitmentMsg> wCommitment)
{
	this->x = x;
	this->c = c;
	this->wCommitment = wCommitment;
}
