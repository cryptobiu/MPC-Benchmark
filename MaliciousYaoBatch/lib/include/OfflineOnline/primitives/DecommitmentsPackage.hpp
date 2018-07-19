#pragma once

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
class DecommitmentsPackage
{
private:
	int hashSize;						//Size of the output of the hash function, in bytes.
	int keySize;						//Size of each key, in bytes.
	int inputSize;						//Size of the input, in bytes.
	int s;								//Security parameter.

	/**
	* The following arguments related to the decommitments: masks, commitments on different wires, ids, etc.
	*/
	vector<byte> idCommitmentsX;
	vector<byte> idCommitmentsR;
	vector<byte> maskCommitmentsX;
	vector<byte> maskCommitmentsR;
	vector<byte> x;
	vector<byte> r;
	vector<byte> diffDecommitmentsX;
	vector<byte> diffDecommitmentsR;
	//vector<vector<shared_ptr<CmtCDecommitmentMessage>>> diffDecommitments;

public:
	DecommitmentsPackage(){}

	/**
	* A constructor that sets the given size parameters and allocate space for the decommitments arrays.
	* @param numCircuits number of circuits to decommit on.
	* @param hashSize Size of the output of the hash function, in bytes.
	* @param keySize Size of each key, in bytes.
	* @param inputSize Size of the input, in bytes.
	* @param s Security parameter.
	*/
	DecommitmentsPackage(size_t numCircuits, int hashSize, int keySize, int inputSize, int s);


	/**
	* Returns a MaskDecommitment of the given index.
	* @param i The index of the mask decommitment that should be returned.
	* @return The CmtCDecommitmentMessage object related to the given index.
	*** Caller needs to Delete. ***
	*/
	shared_ptr<CmtCDecommitmentMessage> getMaskDecommitment(int i);

	/**
	* Sets the maskDecommitments of the given index.
	* @param i The index of the decommitment.
	* @param maskCommitments The decommitment to set.
	*/
	void setMaskDecommitment(int i, shared_ptr<CmtCDecommitmentMessage> maskCommitments);

	/**
	* Returns a IDDecommitment of the given index.
	* @param i The index of the id decommitment that should be returned.
	* @return The CmtCDecommitmentMessage object related to the given index.
	*** Caller needs to Delete. ***
	*/
	shared_ptr<CmtCDecommitmentMessage> getIdDecommitment(int i);

	/**
	* Sets the IDDecommitments of the given index.
	* @param i The index of the decommitment.
	* @param maskCommitments The decommitment to set.
	*/
	void setIdDecommitment(int i, shared_ptr<CmtCDecommitmentMessage> idCommitments);

	/**
	* Sets the X_k value of the diference decommitment.
	* @param k The index of x.
	* @param x The value.
	*/
	void setX(int k, shared_ptr<vector<byte>> newX);

	/**
	*
	* Returns the X_i value of the diference decommitment.
	* @param i The index of the x value that should be returned.
	*/
	shared_ptr<vector<byte>> getX(int i);

	/**
	* Sets the R_k value of the diference decommitment.
	* @param k The index of x.
	* @param xr The random value.
	*/
	void setR(int k, vector<byte> & newR);

	/**
	* Returns the R_i random value of the diference decommitment.
	* @param i The index of the r value that should be returned.
	*/
	shared_ptr<vector<byte>> getR(int k);

	/**
	* Returned the difference commitment ino the given index.
	* @param i The index of the difference commitment that should be returned.
	* @param size The size of the decommitment objects to return.
	* @return Array of size [size] of CmtCDecommitmentMessage objects.
	*** Caller needs to Delete. ***
	*/
	//vector<vector<byte>> getDiffDecommitment(int i, int size);

	vector<vector<byte>> getDiffDecommitmentX(int i, int size);

	vector<vector<byte>> getDiffDecommitmentR(int i, int size);

	/**
	* Sets the given difference decommitment array.
	* @param i The index of the array.
	* @param diffDecommitments The objects to set.
	*/
	void setDiffDecommitments(int i, vector<vector<byte>>& decommitmentsX, vector<vector<byte>>& decommitmentsR);

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & hashSize;
		ar & keySize;
		ar & inputSize;
		ar & s;
		ar & idCommitmentsX;
		ar & idCommitmentsR;
		ar & maskCommitmentsX;
		ar & maskCommitmentsR;
		ar & x;
		ar & r;
		ar & diffDecommitmentsX;
		ar & diffDecommitmentsR;
	}
};
