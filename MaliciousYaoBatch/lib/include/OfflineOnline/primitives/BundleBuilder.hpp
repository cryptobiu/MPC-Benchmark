#pragma once

#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
#include <libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp>
#include <libscapi/include/primitives/PrfOpenSSL.hpp>

#include "../../../include/OfflineOnline/primitives/Bundle.hpp"
#include "../../../include/primitives/KProbeResistantMatrix.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/primitives/SeededRandomnessProvider.hpp"
#include "../../../include/common/aligned_allocator.hpp"
#include "../../../include/common/BinaryUtils.hpp"
#include "../../../include/OfflineOnline/primitives/CommitmentBundle.hpp"


/**
* This class builds the bundle.
* Unlike the Bundle class (that is just a struct that hold data), this class also has functionality that creates
* the inline members.
*
* It contains a build function that garbles the circuit, commit on the keys, etc.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class BundleBuilder
{
private:
	/**
	* Generates a placement mask, which is the signal bits of each wire.
	* @return the generates mask.
	*/
	shared_ptr<vector<byte>> generatePlacementMask(byte* inputWiresX);

protected:
	shared_ptr<GarbledBooleanCircuit> gbc;
	shared_ptr<PrgFromOpenSSLAES> random;
	int keySize;

	// Labels.
	int numberOfInputLabelsP1;
	int numberOfInputLabelsP2;
	size_t numberOfProbeResistantLabels;
	int numberOfOutputLabels;

	// Randomness.
	shared_ptr<OpenSSLAES> mesP2InputKeys;
	shared_ptr<PrgFromOpenSSLAES> randomSourceMasks;
	shared_ptr<PrgFromOpenSSLAES> randomSourceCommitments;
	shared_ptr<PrgFromOpenSSLAES> randomGarble;

	// Wires.
	vec_block_align inputWiresX;
	vec_block_align inputWiresY1;
	vec_block_align inputWiresY1Extended;
	vec_block_align inputWiresY2;
	SecretKey secret;
	
	/**
	* Initializes some random sources that are used in the build process.
	* @param seed To use in order to initialize the random object.
	*/
	void initRandomness(vector<byte> * seed);

	/**
	* Garbles the circuit, then set keys to the additional wires in the protocol.
	* @return The output of the garble function.
	*/
	virtual tuple<block*, block*, std::vector<byte>> garble();

	/**
	* Split Y keys into Y1 and Y2 keys.
	*/
	void splitKeys(block* inputWiresY);

public:
	shared_ptr<KProbeResistantMatrix> matrix;

	/**
	* A constructor that sets the parameters.
	* @param gbc The garbled circuit to use in the bundle.
	* @param matrix The matrix used to extends y1 keys.
	* @param primitives Provides the primitives that are used in the protocol, such as hash function.
	* @param channel The channel communicate between the parties.
	*/
	BundleBuilder(const shared_ptr<GarbledBooleanCircuit> & gbc, const shared_ptr<KProbeResistantMatrix> & matrix);

	~BundleBuilder() {}

	/**
	* Builds the Bundle, meaning garble the inner circuit, commit on it keys, etc.
	* @param seedSizeInBytes The size of the required seed.
	* @return The created Bundle.
	*/
	shared_ptr<Bundle> build(int seedSizeInBytes, shared_ptr<CryptographicHash> & hash);

	/**
	* Builds the Bundle using the given seed.
	* @param seed To use in the build process.
	* @return The created Bundle.
	*/
	shared_ptr<Bundle> build(const shared_ptr<vector<byte>> & seed, const shared_ptr<CryptographicHash> & hash);
};