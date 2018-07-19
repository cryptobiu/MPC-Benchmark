#pragma once
#include <libscapi/include/interactive_mid_protocols/OTBatch.hpp>

#include "../../../include/OfflineOnline/primitives/BucketLimitedBundleList.hpp"
#include "../../../include/primitives/KProbeResistantMatrix.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"

/**
* Runs the receiver side of the malicious OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class OfflineOtReceiverRoutine
{
private:
	shared_ptr<CryptoPrimitives> primitives;							// Primitives objects to use during the protocol execution.
	shared_ptr<OTBatchReceiver> maliciousOtReceiver;		// The inner malicious OT receiver object.
	shared_ptr<KProbeResistantMatrix> matrix;							// Used to transform the inputs from Y1 to Y1 extended.
	size_t originalLabelsSize;											// Labels of Y1 keys.
	size_t m;																// The size of the Y2 extended keys.
	shared_ptr<BucketLimitedBundleList> buckets;						// Contain the circuits.

	/*
	* Needed lengths.
	*/
	int numBuckets;
	int bucketSize;
	int hashSize;
	int keySize;

public:
	/**
	* A constructor that sets the class members.
	* @param execution Contains some parameters used in the OT. For example the bucket size.
	* @param primitives Primitives objects to use during the protocol execution.
	* @param maliciousOtReceiver The inner malicious OT receiver object.
	* @param matrix The matrix to convert the original Y1 input to the Y1 extended inputs.
	* @param channel Used to communicate between the parties in the commitment protocol.
	* In the OT protocol the communication is done in the native code and not using this channel.
	* @param buckets Contain the circuits.
	*/
	OfflineOtReceiverRoutine(shared_ptr<ExecutionParameters> execution, shared_ptr<OTBatchReceiver> maliciousOtReceiver,
		shared_ptr<KProbeResistantMatrix> matrix, shared_ptr<BucketLimitedBundleList> buckets);

	/**
	* Generates inputs and runs the receiver side of the malicious OT protocol.
	*/
	void run(); 

private:
	/**
	* Creates the input object to the OT malicious and executes the OT protocol.
	* @param otInput Contains the input for each input wire.
	* @param bucketId The index of the bucket to work on.
	*/
	void runOtExtensionTransfer(CircuitInput* otInput, int bucketId);

	/**
	* Breaks the output from the OT in to parts. Each part is the garbled Y1 extended key.
	* @param output The output of the malicious OT extension protocol.
	* @param bucketId The index of the bucket to use.
	* @return The garbled output.
	* @throws CheatAttemptException In case the given output was not verified using the commitment.
	*/
	vector<vector<byte>> breakOtOutputArray(vector<byte>& output, int bucketId);

};