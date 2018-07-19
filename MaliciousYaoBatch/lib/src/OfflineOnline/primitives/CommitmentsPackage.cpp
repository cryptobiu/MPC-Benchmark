#include "../../../include/OfflineOnline/primitives/CommitmentsPackage.hpp"

CommitmentsPackage::CommitmentsPackage(int cmtSize, int s)
{
	this->cmtSize = cmtSize;
	this->s = s;
}

void CommitmentsPackage::setSeedCmt(CmtCCommitmentMsg * seedCommitment)
{
	this->seedCmt = std::static_pointer_cast<vector<byte>>(seedCommitment->getCommitment());
	this->seedIds = seedCommitment->getId();
}

void CommitmentsPackage::setMaskCmt(CmtCCommitmentMsg* maskCommitment)
{
	this->maskCmt = std::static_pointer_cast<vector<byte>>( maskCommitment->getCommitment());
	this->maskIds = maskCommitment->getId();
}

void CommitmentsPackage::setCommitmentsX(const shared_ptr<vector<byte>> & commitmentsX, vector<long>* commitmentsXIds)
{
	this->commitmentsX = commitmentsX;
	this->commitmentsXIds = *commitmentsXIds;
}

void CommitmentsPackage::setCommitmentsY1Extended(const shared_ptr<vector<byte>> & commitmentsY1Extended, vector<long>* commitmentsY1ExtendedIds)
{
	this->commitmentsY1Extended = commitmentsY1Extended;
	this->commitmentsY1ExtendedIds = *commitmentsY1ExtendedIds;
}

void CommitmentsPackage::setCommitmentsY2(const shared_ptr<vector<byte>> & commitmentsY2, vector<long>* commitmentsY2Ids)
{
	this->commitmentsY2 = commitmentsY2;
	this->commitmentsY2Ids = *commitmentsY2Ids;
}


vector<vector<vector<byte>>> DiffCommitmentPackage::getDiffCommitments()
{
	//Create and return a CmtCCommitmentMsg[][] from the diffCommitments and diffCommitmentsIds members.
	int size = diffCommitments.size() / (2 * s) / cmtSize;
	vector<vector<vector<byte>>> commitments(size);
	for (int k = 0; k < size; k++) {
		vector<vector<byte>> innerComs(2 * s);
		for (int i = 0; i<2 * s; i++) {
			innerComs[i].resize(cmtSize);
			memcpy(innerComs[i].data(), diffCommitments.data() + k*s * 2 * cmtSize + i*cmtSize, cmtSize);
		}
		commitments[k] = innerComs;
	}
	return commitments;
}

void DiffCommitmentPackage::setDiffCommitments(vector<vector<vector<byte>>>& diffCom)
{
	//Set the given commitmentsX in the diffCommitments and diffCommitmentsIds members.
	int size = diffCom.size();
	diffCommitments.resize(size * 2 * s * cmtSize);
	for (int i = 0; i<size; i++) {
		auto com = diffCom[i];
		int innerSize = com.size();
		for (int k = 0; k<innerSize; k++) {
			memcpy(diffCommitments.data() + i*s * 2 * cmtSize + k*cmtSize, com[k].data(), cmtSize);
		}
	}
}