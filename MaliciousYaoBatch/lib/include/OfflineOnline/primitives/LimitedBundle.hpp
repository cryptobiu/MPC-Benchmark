#pragma once

#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/OfflineOnline/primitives/CommitmentBundle.hpp"
#include "../../../include/primitives/CircuitInput.hpp"
#include "../../../include/CommitmentWithZkProofOfDifference/DifferenceCommitmentReceiverBundle.hpp"

/**
* A bundle is a struct that holds a limited data regarding the protocol. 
*
* These parameters are the garbled table and translation table of the circuit, commitments on the keys and indices of the wires,
* inputs for the circuit, etc. 
*
* The limited bundle is used by p2 during the offline and online phases of the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class LimitedBundle
{
private:
	size_t garbledTableSize;
	block* garbledTables = nullptr;  								// The underlying garbled circuit.
	vector<byte> translationTable;			// Output from the garble function.

	//Wires' indices.
	//Indices of x, y1 extended, y2 and output wires.
	size_t labelsXSize;
	size_t outputLabelsSize;
	size_t labelsY2Size;

	//Commitments on the keys.
	shared_ptr<CommitmentBundle> commitmentsX;
	shared_ptr<CommitmentBundle> commitmentsY1Extended;
	shared_ptr<CommitmentBundle> commitmentsY2;

	shared_ptr<vector<byte>> commitmentsOutput;
	long commitmentsOutputId;
	shared_ptr<CmtCDecommitmentMessage> decommitmentsOutput;
	shared_ptr<DifferenceCommitmentReceiverBundle> diffCommitments;

	//Input for the circuit.
	shared_ptr<CircuitInput> y1 = NULL;
	vector<byte> inputKeysX;
	vector<byte> inputKeysY;
	shared_ptr<vector<byte>> inputKeysY1Extended = NULL;

	//Masks.
	shared_ptr<vector<byte>> placementMaskDifference;
	vector<byte> commitmentMask;

	string tablesFile;

	tuple<vector<byte>, block*> getGarbledTablesFromFile() const;

public:
	LimitedBundle(){}

	/**
	* A constructor.
	*/
	LimitedBundle(block* garbledTables, size_t garbledTableSize, vector<byte> & translationTable, size_t inputLabelsXSize, size_t labelsY2Size, size_t outputLabelsSize,
		const shared_ptr<CommitmentBundle> & commitmentsX, const shared_ptr<CommitmentBundle> & commitmentsY1Extended,
		const shared_ptr<CommitmentBundle> & commitmentsY2, CmtCCommitmentMsg * commitmentsOutput, const shared_ptr<CmtCDecommitmentMessage> & decommitmentsOutput,
		const shared_ptr<DifferenceCommitmentReceiverBundle> & diffCommitments, string& tablesFile);

	/*
	* distractor - free garbledTables
	*/
	~LimitedBundle();

	/*
	* Getters and setters.
	*/
	void setY1(shared_ptr<CircuitInput> y1New) { this->y1 = y1New; }

	shared_ptr<CircuitInput> getY1() { return this->y1; }

	void setXInputKeys(vector<byte> & inputKeys) { inputKeysX = inputKeys; }

	void setYInputKeys(vector<byte> & inputKeys) { this->inputKeysY = inputKeys; }

	void setY1ExtendedInputKeys(shared_ptr<vector<byte>> inputKeys) { this->inputKeysY1Extended = inputKeys; }

	vector<byte> getXInputKeys() { return inputKeysX; }

	vector<byte> getYInputKeys() { return inputKeysY; }

	shared_ptr<vector<byte>> getY1ExtendedInputKeys() { return this->inputKeysY1Extended; }

	void setGarbledTables(block* tables) { this->garbledTables = tables;}
	block* getGarbledTables() { return this->garbledTables; }
    size_t getGarbledTablesSize() {return garbledTableSize; }

	vector<byte> getTranslationTable() { return this->translationTable; }

	size_t getInputLabelsXSize() { return this->labelsXSize; }
	size_t getInputLabelsY2Size() { return this->labelsY2Size; }

	size_t getOutputLabelsSize() { return this->outputLabelsSize; }
	shared_ptr<CommitmentBundle> getCommitmentsX() { return this->commitmentsX; }

	shared_ptr<CommitmentBundle> getCommitmentsY1Extended() { return this->commitmentsY1Extended; }

	shared_ptr<CommitmentBundle> getCommitmentsY2() { return this->commitmentsY2; }

	shared_ptr<vector<byte>> getCommitmentsOutputKeys() { return commitmentsOutput; }

	shared_ptr<CmtCDecommitmentMessage> getDecommitmentsOutputKeys() { return this->decommitmentsOutput; }

	shared_ptr<DifferenceCommitmentReceiverBundle> getDifferenceCommitmentBundle() { return this->diffCommitments; }

	void setPlacementMaskDifference(shared_ptr<vector<byte>> mask) { this->placementMaskDifference = mask; }

	shared_ptr<vector<byte>> getPlacementMaskDifference() { return this->placementMaskDifference; }

	void setCommitmentMask(vector<byte> & mask) { this->commitmentMask = mask; }

	vector<byte> getCommitmentMask() { return commitmentMask; }

	friend class boost::serialization::access;
	template<class Archive>
	void save(Archive & ar, const unsigned int version) const;

	template<class Archive>
	void load(Archive & ar, const unsigned int version);

	BOOST_SERIALIZATION_SPLIT_MEMBER()
};

template<class Archive>
inline void LimitedBundle::save(Archive & ar, const unsigned int version) const
{
	vector<byte> garbledTablesToSend;
	tuple<vector<byte>, block*> garbledTablesNew;
	//read garbledTables from file
	if (!this->tablesFile.empty())
	{
		garbledTablesNew = getGarbledTablesFromFile();
		garbledTablesToSend = get<0>(garbledTablesNew);
	}
	else
	{
		size_t byteNum = this->garbledTableSize;
		byte* temp = (byte*)garbledTables;

		garbledTablesToSend.resize(byteNum);
		//make byte vector of block*
		memcpy(garbledTablesToSend.data(), temp, byteNum);
		//garbledTablesToSend = vector<byte>(temp, temp + byteNum);
	}

	
	ar & translationTable;
	ar & garbledTableSize;
	for (int i = 0; i < garbledTableSize; i++) {
		ar & garbledTablesToSend[i];
	}
	//ar & garbledTablesToSend;
	ar & labelsXSize;
	ar & labelsY2Size;
	ar & outputLabelsSize;
	ar & commitmentsX;
	ar & commitmentsY1Extended;
	ar & commitmentsY2;
	ar & commitmentsOutput;
	ar & commitmentsOutputId;
	ar & decommitmentsOutput;
	ar & diffCommitments;
	ar & y1;
	ar & inputKeysX;
	ar & inputKeysY;
	ar & inputKeysY1Extended;
	ar & placementMaskDifference;
	ar & commitmentMask;

	if (!this->tablesFile.empty())
	{
		_mm_free(get<1>(garbledTablesNew));
	}
}

template<class Archive>
inline void LimitedBundle::load(Archive & ar, const unsigned int version)
{
	
	ar & translationTable;
	ar & garbledTableSize;
	//convert from vector<byte> to block*
	garbledTables = (block *)_mm_malloc(garbledTableSize, 16);
	//memcpy((byte*)garbledTables, readGarbledTables.data(), readGarbledTables.size());
	//readGarbledTables.resize(garbledTableSize);
	for (int i = 0; i < garbledTableSize; i++) {
		ar & ((byte*)garbledTables)[i];
	}
	//ar & readGarbledTables;
	ar & labelsXSize;
	ar & labelsY2Size;
	ar & outputLabelsSize;
	ar & commitmentsX;
	ar & commitmentsY1Extended;
	ar & commitmentsY2;
	ar & commitmentsOutput;
	ar & commitmentsOutputId;
	ar & decommitmentsOutput;
	ar & diffCommitments;
	ar & y1;
	ar & inputKeysX;
	ar & inputKeysY;
	ar & inputKeysY1Extended;
	ar & placementMaskDifference;
	ar & commitmentMask;

}
