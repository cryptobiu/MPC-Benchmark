#pragma once

#include <libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>
#include "../../../include/common/CommonMaliciousYao.hpp"

/**
* This package gathering together some objects that should be sent over the offline protocol.
*
* In order to be as fast as we can, we send a group of thing instead of every one of them alone.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class CommitmentsPackage {
private:
	int cmtSize;				//Size of every commitment, in bytes.
	int s;							//Security parameter.

	/**
	* The following arguments related to the commitments: masks, commitments on different wires, ids, etc.
	*/
	shared_ptr<vector<byte>> seedCmt;
	long seedIds;
	shared_ptr<vector<byte>> maskCmt;
	long maskIds;
	shared_ptr<vector<byte>> commitmentsX;
	vector<long> commitmentsXIds;
	shared_ptr<vector<byte>> commitmentsY1Extended;
	vector<long> commitmentsY1ExtendedIds;
	shared_ptr<vector<byte>> commitmentsY2;
	vector<long> commitmentsY2Ids;
	shared_ptr<vector<byte>> commitmentsOutputKeys;
	
public:
	CommitmentsPackage() { cmtSize = 20; }
	/**
	* A constructor that sets the given parameters.
	* @param cmtSize Size of every commitment, in bytes.
	* @param s Security parameter.
	*/
	CommitmentsPackage(int cmtSize, int s);

	
	// Setters and getters for each class member.
	
	void setSeedCmt(CmtCCommitmentMsg* seedCommitment);

	/*
	 Create new CmtCCommitmentMsg.
	*** Caller needs to Delete. ***
	*/
	CmtCCommitmentMsg* getSeedCmt() { return new CmtSimpleHashCommitmentMessage(seedCmt, seedIds); }

	void setMaskCmt(CmtCCommitmentMsg* maskCommitment);

	/*
	Create new CmtCCommitmentMsg.
	*** Caller needs to Delete. ***
	*/
	CmtCCommitmentMsg* getMaskCmt() { return new CmtSimpleHashCommitmentMessage(maskCmt, maskIds); }

	shared_ptr<vector<byte>> getCommitmentsX() { return commitmentsX; }

	vector<long>& getCommitmentXIds() { return commitmentsXIds; }

	void setCommitmentsX(const shared_ptr<vector<byte>> & commitmentsX, vector<long>* commitmentsXIds);

	shared_ptr<vector<byte>> getCommitmentsY1Extended() { return commitmentsY1Extended; }

	vector<long>& getCommitmentY1ExtendedIds() { return commitmentsY1ExtendedIds; }

	void setCommitmentsY1Extended(const shared_ptr<vector<byte>> & commitmentsY1Extended, vector<long>* commitmentsY1ExtendedIds);

	shared_ptr<vector<byte>> getCommitmentsY2() { return commitmentsY2; }

	vector<long>& getCommitmentY2Ids() { return commitmentsY2Ids; }

	void setCommitmentsY2(const shared_ptr<vector<byte>> & commitmentsY2, vector<long>* commitmentsY2Ids);

	/*
	Create and return a CmtCCommitmentMsg from the commitmentsOutputKeys.
	*** Caller needs to Delete. ***
	*/
	CmtCCommitmentMsg* getCommitmentsOutputKeys() {return new CmtSimpleHashCommitmentMessage(commitmentsOutputKeys, 0); }

	/*
	 Set the given commitmentsX in the commitmentsOutputKeys and commitmentsOutputKeysIds members.
	*/
	void setCommitmentsOutputKeys(CmtCCommitmentMsg* output) {
		this->commitmentsOutputKeys = std::static_pointer_cast<vector<byte>>(output->getCommitment());
	}

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & cmtSize;
		ar & s;
		ar & seedCmt;
		ar & seedIds;
		ar & maskCmt;
		ar & maskIds;
		ar & commitmentsX;
		ar & commitmentsXIds;
		ar & commitmentsY1Extended;
		ar & commitmentsY1ExtendedIds;
		ar & commitmentsY2;
		ar & commitmentsY2Ids;
		ar & commitmentsOutputKeys;
	}

};


class DiffCommitmentPackage {
private:
	int cmtSize;				//Size of every commitment, in bytes.
	int s;							//Security parameter.
	vector<byte> diffCommitments;
	//vector<long> diffCommitmentsIds;
	//vector<vector<shared_ptr<CmtCCommitmentMsg>>> diffCommitments;

public:
	DiffCommitmentPackage() {}
	DiffCommitmentPackage(int cmtSize, int s) :cmtSize(cmtSize), s(s) {}

	/*
	Create and return a CmtCCommitmentMsg[][] from the diffCommitments and diffCommitmentsIds members.
	*** Caller needs to Delete. ***
	*/
	vector<vector<vector<byte>>> getDiffCommitments();

	/*
	Set the given commitmentsX in the diffCommitments and diffCommitmentsIds members.
	*/
	void setDiffCommitments(vector<vector<vector<byte>>>& diffCommitments);

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & cmtSize;
		ar & s;
		ar & diffCommitments;
		//ar & diffCommitmentsIds;
	}
};

