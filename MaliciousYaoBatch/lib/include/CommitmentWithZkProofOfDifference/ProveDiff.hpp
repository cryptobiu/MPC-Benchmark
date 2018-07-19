#pragma once

#include "../../include/common/CommonMaliciousYao.hpp"
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>

/**
* This message is sent during the input consistency protocol in the offline phase.
*
* This message gather some small messages in order to make the sending more efficient, since sending small messages is less
* efficient than a big message.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar - Ilan University
*
*/
class ProveDiff
{
private:
	vector<byte> committedDifference;		
	vector<byte> delta;
	size_t n;									//The total number of circuits. (checked + eval)
	int s;									//Security parameter. Indicates how much commitments pairs will be.

public:
	ProveDiff(){}
	/**
	* A constructor that sets the parameters.
	* @param numCircuits number of secrets.
	* @param n The total number of circuits. (checked + eval)
	* @param s Security parameter.
	*/
	ProveDiff(int numCircuits, size_t n, int s);

	/**
	* Returns the committed difference from the given index in the committedDifference class member.
	* @param i The index of the committed difference to return.
	*/
	vector<byte> getCommittedDifference(size_t i);

	/**
	* Sets the given committed difference in the given index in the committedDifference inline member.
	* @param i The index where to put the given committedDifference.
	* @param committedDifference The value to put.
	*/
	void setCommittedDifference(size_t i, vector<byte>& committedDifferenceNew);

	/**
	* Returns the delta array from of the given index in the delta class member.
	* @param i The index to take the delta from.
	*/
	vector<byte> getDelta(size_t i);

	/**
	* Sets the given delta in the given index in the delta inline member.
	* @param i The index where to put the given delta.
	* @param delta The value to put.
	*/
	void setDelta(size_t i, vector<byte> & deltaNew);

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & n;
		ar & s;
		ar & committedDifference;
		ar & delta;
	}
};


class ProveDecommitments {
private:
	vector<byte> decommitmentsX;
	vector<byte> decommitmentsR;
	int xSize, rSize;
public:
	
	ProveDecommitments() {}
	ProveDecommitments(vector<byte> & decommitmentsX, int xSize, vector<byte> & decommitmentsR, int rSize);

	/**
	* Returns the committed difference from the given index in the committedDifference class member.
	* @param i The index of the committed difference to return.
	*/
	vector<shared_ptr<CmtCDecommitmentMessage>> getDecommitments();
	vector<byte> getDecommitmentsX() {	return decommitmentsX;	}
	vector<byte> getDecommitmentsR() { return decommitmentsR; }
	int getXSize() { return xSize; }

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & xSize;
		ar & rSize;
		ar & decommitmentsX;
		ar & decommitmentsR;
	}
};