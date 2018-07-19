#pragma once

#include <libscapi/include/interactive_mid_protocols/OTBatch.hpp>

#include "../../../include/OfflineOnline/primitives/BucketBundleList.hpp"
#include "../../../include/primitives/KProbeResistantMatrix.hpp"
#include "../../../include/primitives/ExecutionParameters.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/common/KeyUtils.hpp"

using namespace std;

/**
* Runs the sender side of the malicious OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class OfflineOtSenderRoutine 
{
private:
	shared_ptr<OTBatchSender> maliciousOtSender;			// The inner malicious OT sender object.
	shared_ptr<BucketBundleList> buckets;							// Contain the circuits.

	/*
	* Needed lengths.
	*/
	int numBuckets;
	int bucketSize;
	int hashSize;
	int keySize;
	size_t m;												// The size of the Y2 extended keys.

	/**
	* Returns the garbled input of the given party.
	* @param bucketId The index of the bucket to work on.
	* @param b Indicates which party to get the inputs of. 0 for the first party and 1 for the second.
	*/
	vector<byte> buildInput(int bucketId, int b);

	/**
	* Creates the input for the OT sender and executes the OT protocol.
	* @param bucketId The index of the bucket to work on.
	*/
	void runOtExtensionTransfer(int bucketId);

public:
	/**
	* A constructor that sets the class members.
	* @param execution Contains some parameters used in the OT. For example the bucket size.
	* @param primitives Primitives objects to use during the protocol execution.
	* @param maliciousOtSender The inner malicious OT sender object.
	* @param matrix The matrix to convert the original Y1 input to the Y1 extended inputs.
	* @param buckets Contain the circuits.
	*/
	OfflineOtSenderRoutine(const shared_ptr<ExecutionParameters>& execution, const shared_ptr<KProbeResistantMatrix> & matrix, 
		const shared_ptr<BucketBundleList> & buckets, const shared_ptr<OTBatchSender> & maliciousOtSender);

	/**
	* Runs the sender side of the malicious OT protocol for each bucket.
	*/
	void run();
};
