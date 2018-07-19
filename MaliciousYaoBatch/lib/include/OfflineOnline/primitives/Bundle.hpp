#pragma once

#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
#include <libscapi/include/cryptoInfra/Key.hpp>
#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/OfflineOnline/primitives/CommitmentBundle.hpp"
#include "../../../include/CommitmentWithZkProofOfDifference/DifferenceCommitmentCommitterBundle.hpp"
#include "../../../include/OfflineOnline/primitives/CommitmentsPackage.hpp"
#include "../../../include/common/aligned_allocator_no_destructor.hpp"

/**
 A bundle is a struct that holds a garbled circuit along with all of the circuit's parameters. 

 These parameters are the input and output keys, translation table, masks, extended keys, commitments on the keys and more. 

 The bundle is used during the offline and the online phases of the protocol.
*/

class Bundle {
private:
	shared_ptr<vector<byte>> seed;
	int garbledTableSize;
	block* garbledTables = nullptr;  						// The underlying garbled circuit.
	vector<byte> translationTable;			// Output from the garble function.

	//Masks that are used in the protocol.
	shared_ptr<vector<byte>> placementMask;
	shared_ptr<vector<byte>>commitmentMask;

	//Indices of x, y1 extended, y2 and output wires.
	int inputLabelsXSize;
	int labelsY2Size;

	//Additional keys besides the above wires' indices.
	vec_block_align inputWiresY1Extended;
	int numberOfOutputs;
	block* outputWires = nullptr;

	//Commitments on the keys.
	shared_ptr<CommitmentBundle> commitmentsX;
	shared_ptr<CommitmentBundle> commitmentsY1Extended;
	shared_ptr<CommitmentBundle> commitmentsY2;

	SecretKey secret;

	shared_ptr<DifferenceCommitmentCommitterBundle> diffCommitments;

	int keySize;	//Size of each key, in bytes.

	shared_ptr<CmtCCommitmentMsg> commitment;
	shared_ptr<CmtCDecommitmentMessage> decommit;

public:
	//Bundle():outputWires(nullptr){}
	Bundle(){}

	/**
	* A constructor.
	*/
	Bundle(const shared_ptr<vector<byte>> & seed, const shared_ptr<GarbledBooleanCircuit> & garbledCircuit, block * wireValues, int numberOfOutputs,
		const shared_ptr<vector<byte>> & placementMask, const shared_ptr<vector<byte>> & commitmentMask, int inputLabelsXSize,
		int labelsY2Size, vec_block_align & inputWiresY1Extended,
		const shared_ptr<CommitmentBundle> & commitmentsX, const shared_ptr<CommitmentBundle> & commitmentsY1Extended,
		const shared_ptr<CommitmentBundle> & commitmentsY2, const shared_ptr<CmtCCommitmentMsg> & commitment, const shared_ptr< CmtCDecommitmentMessage> & decommit,
		SecretKey & secret, int keySize);

	/*
	* A destructor.
	*/
	~Bundle() {
		if (outputWires != nullptr)
			_mm_free(outputWires);
		if (garbledTables != nullptr)
		_mm_free(garbledTables);
	}

	int getGarbledTableSize() { return garbledTableSize; }
	shared_ptr<vector<byte>> getSeed() { return seed; }
	vector<byte> getTranslationTable() { return translationTable;	}
	shared_ptr<vector<byte>> getPlacementMask() { return placementMask; }
	shared_ptr<vector<byte>> getCommitmentMask() {	return commitmentMask; }
	int getNumberOfInputLabelsX() {	return inputLabelsXSize; }
	int getInputLabelsY2Size() { return labelsY2Size; }
	int getNumberOfOutputLabels() { return numberOfOutputs; }
	vec_block_align getInputWiresY1Extended() { return inputWiresY1Extended; }
	block getOutputWiresAt(int index) { return outputWires[index]; }
	shared_ptr<CommitmentBundle> getCommitmentsX() { return commitmentsX; }
	shared_ptr<CommitmentBundle> getCommitmentsY1Extended() { return commitmentsY1Extended; }
	shared_ptr<CommitmentBundle> getCommitmentsY2() { return commitmentsY2; }
	shared_ptr<CmtCCommitmentMsg> getCommitmentsOutputKeys() { return commitment; }
	shared_ptr<CmtCDecommitmentMessage> getDecommitmentsOutputKeys() { return decommit; }

	block* getGarbledTables() {
		//TODO **** CHECKUP - check delete
		/*block* temp = this->garbledTables;
		this->garbledTables = NULL;
		return temp;*/
		return this->garbledTables;
	}

	block getProbeResistantWire(size_t wireIndex, int sigma);

	/**
	* Put in the commitment package the commitments on X, Y1Extended, Y2 and ouptut keys.
	* @param pack CommitmentsPackage that should be filled with the commitments.
	*/
	void getCommitments(CommitmentsPackage & pack);

	void setDifferenceCommitmentBundle(shared_ptr<DifferenceCommitmentCommitterBundle> bundle) { this->diffCommitments = bundle; }

	shared_ptr<DifferenceCommitmentCommitterBundle> getDifferenceCommitmentBundle() { return this->diffCommitments; }

	SecretKey getSecret() { return this->secret; }

	vector<byte> getGarbleTableToSend();

	// This method lets cereal know which data members to save to file
	friend class boost::serialization::access;
	template<class Archive>
	void save(Archive & ar, const unsigned int version) const;

	// This method lets cereal know which data members to load to file
	template<class Archive>
	void load(Archive & ar, const unsigned int version);

	BOOST_SERIALIZATION_SPLIT_MEMBER()
};
template<class Archive>
inline void Bundle::save(Archive & ar, const unsigned int version) const
{
	//in order to send ouptutWires - block*, we need to make vector byte and send it.
	int byteNum = SIZE_OF_BLOCK * 2 * this->numberOfOutputs;
	byte* temp = (byte*)outputWires;
	//make byte vector of block*
	vector<byte> outputWiresToSend(temp, temp + byteNum);

	ar & seed;
	ar & placementMask;
	ar & commitmentMask;
	ar & inputLabelsXSize;
	ar & labelsY2Size;
	ar & commitmentsX;
	ar & commitmentsY1Extended;
	ar & commitmentsY2;
	ar & diffCommitments;
	ar & keySize;
	ar & numberOfOutputs;
	//ar & outputWiresToSend;
	for (int i = 0; i < SIZE_OF_BLOCK * 2 * numberOfOutputs; i++) {
		ar & outputWiresToSend[i];
	}
	ar & secret;
	ar & commitment;
	ar & decommit;
}

template<class Archive>
inline void Bundle::load(Archive & ar, const unsigned int version)
{
	
	ar & seed;
	ar & placementMask;
	ar & commitmentMask;
	ar & inputLabelsXSize;
	ar & labelsY2Size;
	ar & commitmentsX;
	ar & commitmentsY1Extended;
	ar & commitmentsY2;
	ar & diffCommitments;
	ar & keySize;
	ar & numberOfOutputs;

	//read outputWires to vector<byte> align to 16 with no destractor
	//vector<byte> readOutputWires(SIZE_OF_BLOCK * 2 * numberOfOutputs);
	outputWires = (block *)_mm_malloc(SIZE_OF_BLOCK * 2 * numberOfOutputs, 16);
	for (int i = 0; i < SIZE_OF_BLOCK * 2 * numberOfOutputs; i++) {
		ar & ((byte*)outputWires)[i];
	}
	//ar & readOutputWires;
	ar & secret;
	ar & commitment;
	ar & decommit;
}
