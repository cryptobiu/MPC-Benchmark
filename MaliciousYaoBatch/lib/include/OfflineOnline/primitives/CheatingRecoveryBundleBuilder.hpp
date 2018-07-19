#pragma once

#include "../../../include/OfflineOnline/primitives/BundleBuilder.hpp"
#include "../../../include/primitives/CircuitInput.hpp"

/**
* This class builds the bundle of the Cheating recover circuit. 
*
* It derives the BundleBuilder class and add the proof of cheating functionalities.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class CheatingRecoveryBundleBuilder : public BundleBuilder
{
private:
	shared_ptr<CircuitInput> proofOfCheating;	// A proof that the other party is cheating.

	/**
	* Generates P2 keys according to the master key.
	* @param masterKey The one key of P1.
	* @param sigmaArray bytes of proof of cheating.
	*/
	void generateYKeys(block &masterKey, const shared_ptr<vector<byte>> & sigmaArray, block &delta, vec_block_align & inputWiresY);
	
protected:
	/**
	* Garbles the circuit, then set keys to the additional wires in the protocol.
	* @return The output of the garble function.
	*/
	tuple<block*, block*, std::vector<byte>> garble() override;

public:
	/**
	* A constructor that sets the parameters.
	* @param gbc The garbled circuit to use in the bundle.
	* @param matrix The matrix used to extends y1 keys.
	* @param primitives Provides the primitives that are used in the protocol, such as hash function.
	* @param channel The channel communicate between the parties.
	* @param proofOfCheating A proof that the other party is cheating.
	*/
	CheatingRecoveryBundleBuilder(const shared_ptr<GarbledBooleanCircuit> & gbc, const shared_ptr<KProbeResistantMatrix> & matrix, SecretKey & proofOfCheating);


};