#pragma once
#include <vector>
#include <libscapi/include/infra/Common.hpp>
#include <libscapi/include/interactive_mid_protocols/RandomValue.hpp>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>

using namespace std;

/**
* This package is being filled in the online protocol by p1 and sent to p2. <p>
*
* This way, there is only one send instead of sending each member alone; This saves time.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class EvaluationPackage{
private:
	//The following members needed in the online protocol.

	//Masks.
	vector<byte> placementMasks;
	vector<byte> commitmentMasks;
	vector<byte> maskOnD2Input;

	//Decommitments on the keys.
	vector<byte> decommitmentsY2InputKeysX;
	vector<byte> decommitmentsY2InputKeysR;
	vector<byte> decommitmentsXInputKeysX;
	vector<byte> decommitmentsXInputKeysR;

	vector<byte> decommitmentsOutputKeysX;
	vector<byte> decommitmentsOutputKeysR;

	//Proof of cheating.
	vector<byte> xoredProofOfCheating;
	vector<byte> hashedProofOfCheating;
	vector<byte> proofOfCheating;

public:
	/*
	* Getters and setters for each class member.
	*/
	void setCommitmentMask(vector<byte> & commitmentMask) {
		this->commitmentMasks = commitmentMask;
	}

	vector<byte> getCommitmentMask() {
		return commitmentMasks;
	}

	void setDecommitmentsToY2InputKeys(vector<byte> & x, vector<byte>&  r) {
		this->decommitmentsY2InputKeysX = x;
		this->decommitmentsY2InputKeysR = r;
	}

	void setDecommitmentsToXInputKeys(vector<byte>&  x, vector<byte> & r) {
		this->decommitmentsXInputKeysX = x;
		this->decommitmentsXInputKeysR = r;
	}

	void setDecommitmentsToOutputKeys(vector<byte> & x, vector<byte> & r) {
		this->decommitmentsOutputKeysX = x;
		this->decommitmentsOutputKeysR = r;
	}

	/**
	* Returns Decommitment to Y2 input keys, according to the given circuit id and the index.
	* @param circuitId The circuit that the requested decommitment belongs.
	* @param index The index of the y2 input wire that the decommitment belongs.
	* @param numWires number of input wires.
	* @param keySize The size of each key, in bytes.
	* @param hashSize The size of the decommitment, in bytes.
	*/
	//CmtSimpleHashDecommitmentMessage getDecommitmentToY2InputKey(int circuitId, size_t index, size_t numWires, int keySize, int hashSize);
	vector<byte> & getRandomDecommitmentY2InputKey() { return decommitmentsY2InputKeysR; }
	vector<byte> & getXDecommitmentY2InputKey() { return decommitmentsY2InputKeysX; }
	/**
	* Returns Decommitment to X input keys, according to the given circuit id and the index.
	* @param circuitId The circuit that the requested decommitment belongs.
	* @param index The index of the x input wire that the decommitment belongs.
	* @param numWires number of input wires.
	* @param keySize The size of each key, in bytes.
	* @param hashSize The size of the decommitment, in bytes.
	*/
	//CmtSimpleHashDecommitmentMessage getDecommitmentToXInputKey(size_t circuitId, size_t index, size_t numWires, int keySize, int hashSize);
	vector<byte> & getRandomDecommitmentXInputKey() { return decommitmentsXInputKeysR; }
	vector<byte> & getXDecommitmentXInputKey() { return decommitmentsXInputKeysX; }
	/**
	* Returns Decommitment to output key, according to the given circuit id.
	* @param circuitId The circuit that the requested decommitment belongs.
	* @param numWires number of output wires.
	* @param keySize The size of each key, in bytes.
	* @param hashSize The size of the decommitment, in bytes.
	*/
	//CmtSimpleHashDecommitmentMessage getDecommitmentToOutputKey(size_t circuitId, size_t numWires, int keySize, int hashSize);
	vector<byte> & getRandomDecommitmentOutputKey() { return decommitmentsOutputKeysR; }
	vector<byte> & getXDecommitmentOutputKey() { return decommitmentsOutputKeysX; }

	void addMaskOnD2(vector<byte> maskOnD2InputNew) { this->maskOnD2Input = maskOnD2InputNew;	}

	vector<byte> getMaskOnD2() { return maskOnD2Input; }

	void setPlacementMask(vector<byte> placementMask) {	this->placementMasks = placementMask; }

	vector<byte> getPlacementMask() { return placementMasks; }

	void setXoredProofOfCheating(vector<byte> proofParts) { xoredProofOfCheating = proofParts; }

	/**
	* Returns the xored proof, according to the given circuit id, index and sigma.
	* @param wireIndex The index of the wire that the proof belongs.
	* @param circuitId The circuit that the requested proof belongs.
	* @param sigma Indicates which proof to return (there are two proofs for each wire.)
	* @param numCircuits number of circuits.
	* @param keySize The size of each key, in bytes.
	*/
	block getXoredProof(size_t wireIndex, size_t circuitId, int sigma, size_t numCircuits, int keySize);

	void setHashedProofOfCheating(vector<byte>& hashedProof) { this->hashedProofOfCheating = hashedProof; }

	vector<byte> getHashedProof() { return hashedProofOfCheating; }

	void addProofOfCheating(vector<byte> proofOfCheatingNew) {	this->proofOfCheating = proofOfCheatingNew; }

	vector<byte> getProofOfCheating() {	return proofOfCheating;	}

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & placementMasks;
		ar & commitmentMasks;
		ar & maskOnD2Input;
		ar & decommitmentsY2InputKeysX;
		ar & decommitmentsY2InputKeysR;
		ar & decommitmentsXInputKeysX;
		ar & decommitmentsXInputKeysR;
		ar & decommitmentsOutputKeysX;
		ar & decommitmentsOutputKeysR;
		ar & xoredProofOfCheating;
		ar & hashedProofOfCheating;
		ar & proofOfCheating;
	}
};

