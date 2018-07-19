#pragma once
#include "../../common/CommonMaliciousYao.hpp"
#include "../primitives/BucketLimitedBundle.hpp"
#include "../../primitives/CryptoPrimitives.hpp"
#include "../../common/KeyUtils.hpp"
#include "../../primitives/CutAndChooseSelection.hpp"
#include "../../common/BinaryUtils.hpp"

#include <libscapi/include/primitives/Hash.hpp>
#include <libscapi/include/primitives/Kdf.hpp>
#include <libscapi/include/primitives/Prf.hpp>


/**
* An interface that provides functionality regarding the circuit evaluation. <P>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class ComputeCircuitsRoutine {

public:
	/**
	* Computes the inline circuits.
	*/
	virtual void computeCircuits() = 0;

	/**
	* After evaluating the circuits, an output analysis should be executed in order to detect cheating.
	* In case of cheating, a proof of the cheating is achieved and saved in the derived object.
	* @return CircuitEvaluationResult Contains one of the folowing three posibilities:
	* 								1. VALID_OUTPUT
	* 								2. INVALID_WIRE_FOUND
	* 								3. FOUND_PROOF_OF_CHEATING.
	*/
	virtual CircuitEvaluationResult runOutputAnalysis() = 0;

	/**
	* Returns the output of the circuits.
	*/
	virtual vector<byte> getOutput() = 0;
};

/**
* This class computes the circuits and returns the output.
*
* It also achieves the proof of cheating in case not all the circuits output the same result.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class OnlineComputeRoutine : public ComputeCircuitsRoutine {

private:
	vector<shared_ptr<GarbledBooleanCircuit>> circuits;		// The circuits to work on. There is one circuit per thread.
	
	// Primitives objects to use in the compute step.
	shared_ptr<CryptographicHash> hash;
	shared_ptr<HKDF> kdf;
	shared_ptr<AES> aes;
	shared_ptr<PrgFromOpenSSLAES> prg;
	shared_ptr<BucketLimitedBundle> bucket;
	int keyLength;
	int numOfThreads;

	// The proof of cheating in case no all the circuits output the same result.
	vector<vector<vector<block>>> proofCiphers;
	SecretKey hashedProof;

	// The output of the compute step.
	vector<block*> computedOutputWires;
	vector<vector<byte>> translations;
	SecretKey proofOfCheating;
	int correctCircuit = -1;

	/**
	* Computes the circuits from the start point to the end point in the circuit list.
	* @param from The first circuit in the circuit list that should be computed.
	* @param to The last circuit in the circuit list that should be computed.
	*/
	void computeCircuit(size_t from, size_t to, int index);

	/**
	* Extract proof of cheating for the given wire index.
	* If there was no cheating, return null key.
	* @param wireIndex The wire index to check for cheating.
	* @return the proof of cheating in case there was a cheating; null, otherwise.
	* @throws InvalidKeyException
	* @throws InvalidInputException
	*/
	SecretKey extractProofOfCheating(int wireIndex);

public:
	/**
	* A constructor that sets the given parameters.
	* @param garbledCircuits The circuits to work on. There is one circuit per thread.
	* @param primitives Primitives objects to use in the compute step.
	* @param enc Used to extract the proof of cheating.
	* @param proofCiphers Used to extract the proof of cheating.
	* @param hashedProof Used to extract the proof of cheating.
	*/
	OnlineComputeRoutine(vector<shared_ptr<GarbledBooleanCircuit>> & garbledCircuit, const shared_ptr<BucketLimitedBundle> & bucket,
		vector<vector<vector<block>>> & proofCiphers, SecretKey & hashedProof);

    ~OnlineComputeRoutine(){
        for(auto output : computedOutputWires){
            _mm_free(output);
        }
    }

	void computeCircuits() override;

	CircuitEvaluationResult runOutputAnalysis() override;

	vector<byte> getOutput() override;

	void setCorrectCircuit(size_t j) {	correctCircuit = j;	}

	/**
	* Returns the proof of cheating.
	* In case there was no cheating, returns a dummy secret key.
	*/
	SecretKey getProofOfCheating() { return proofOfCheating; }

	block* getComputedOutputWires(size_t circuitIndex) { return computedOutputWires[circuitIndex]; }
};

/**
* This class computes the circuits and returns the majority output.
*
* By majority output we mean that for each output wire, return the output that most of the circuits outputs.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class MajoriryComputeRoutine : public ComputeCircuitsRoutine {
private:
	CutAndChooseSelection selection;				// Indicates which circuit is checked and which is evaluated.
	vector<shared_ptr<GarbledBooleanCircuit>> circuits;		// The circuits to work on. There is one circuit per thread.
	shared_ptr<BucketLimitedBundle> bucket;
	vector<vector<byte>> allOutputs;				// Contains the output of each circuit.
	vector<byte> majorityOutput;					// The output of majority of the circuits.
	int keyLength;

	/**
	* Computes the circuits from the start point to the end point in the circuit list.
	* @param from The first circuit in the circuit list that should be computed.
	* @param to The last circuit in the circuit list that should be computed.
	*/
	void computeCircuit(size_t from, size_t to, int index);

	/**
	* Returns the output with the highest counter.
	* @param map Contains for each output wire all the optional outputs.
	*/
	byte getKeyWithMaxValue(vector<int> & map);

public:
	/**
	* A constructor that sets the given parameters.
	* @param selection Indicates which circuit is checked and which is evaluated.
	* @param garbledCircuits The circuits to work on. There is one circuit per thread.
	* @param primitives Contains some primitives objects to use during the protocol.
	*/
	MajoriryComputeRoutine(CutAndChooseSelection & selection, vector<shared_ptr<GarbledBooleanCircuit>> & garbledCircuits, shared_ptr<BucketLimitedBundle> bucket);

	void computeCircuits() override;


	CircuitEvaluationResult runOutputAnalysis() override;

	/**
	* Returns the majority output. Meaning, for each output wire, return the output that most of the circuits outputs.
	*/
	vector<byte> getOutput() override {	return majorityOutput; }
};


