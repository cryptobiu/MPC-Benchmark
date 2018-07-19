#pragma once

#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>

#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/primitives/ExecutionParameters.hpp"
#include "../../../include/OfflineOnline/primitives/BundleBuilder.hpp"
#include "../../../include/OfflineOnline/primitives/BucketBundleList.hpp"
#include "../../../include/primitives/CutAndChooseSelection.hpp"
#include "../../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceCommitter.hpp"
#include "../../../include/OfflineOnline/primitives/DecommitmentsPackage.hpp"
#include "../../common/LogTimer.hpp"


/**
* This is the Cut And Choose prover used in the protocol.
*
* The cut and choose paradigm is an important building block in the offline/online Yao protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class CutAndChooseProver
{
private:
	shared_ptr<ExecutionParameters> execution;		//Contains parameters regarding the execution. 
	vector<shared_ptr<CommParty>> commParty;				// The channel that communicates between the parties.
	vector<shared_ptr<BundleBuilder>> bundleBuilders;		// Contains the circuit parameters used to build the circuit.
	int numCircuits;
	shared_ptr<CmtSimpleHashCommitter> cmtSender;				//Used to commit and decommit during the protocol.
	shared_ptr<CmtReceiver> cmtReceiver;			//Used to receive the commitment and decommitment from the cut and choose verifier. 

	shared_ptr<CmtWithDifferenceCommitter> diffProtocol;
	vector<shared_ptr<Bundle>> circuitBundles;		//Contains the garbled circuit.
	shared_ptr<CmtRCommitPhaseOutput> selectionCommitment;		//Commitment of the selection. Received from the cut and choose verifier. 
	shared_ptr<CmtRCommitPhaseOutput> mappingCommitment;		//Commitment of the mapping. Received from the cut and choose verifier. 

	shared_ptr<CutAndChooseSelection> selection;				//The cut and choose selection. Received from the cut and choose verifier after verifying the commitment.
	shared_ptr<BucketMapping> bucketMapping;					//The mapping of the circuits to bundles. Received from the cut and choose verifier after verifying the commitment.
	shared_ptr<BucketBundleList> buckets;						//List of buckets containing the circuits according to the above mapping.

	/**
	* Put the evaluated circuits in buckets, according to the mapping algorithm received from the cut and choose verifier.
	*/
	void putCircuitsInBuckets();

	/**
	* Garbles each circuit, then commit on its keys.
	* @throws IOException
	*/
	void constructGarbledCircuitBundles();

	/**
	* Garble the circuit in the given index j using the bundle builder of the given index i.
	* @param j The index in the circuit list where the circuit that should be garbled is placed.
	* @throws IOException
	*/
	void buildCircuit(int from, int to, int threadIndex);

	/**
	* Receives from the cut and choose verifier the commitment on the cut and choose selection and the mapping of the circuit into buckets.
	* @throws ClassNotFoundException
	* @throws IOException
	*/
	void receiveCommitmentToCutAndChoose();

	/**
	* Generate and send the cut and choose commitments.
	* The commitments are on the seeds, masks, keys of every circuit bundles and also the commitments on B[0], ..., B[j-1].
	* @throws IOException In case there is a problem during the communication.
	*/
	void sendCommitments();

	/**
	* Receive Decommitments of the cut and choose selection and the circuits mapping.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void receiveCutAndChooseChallenge();

	/**
	* Prove the checked circuits by decommiting on the seed, mask and keys of each selected circuit.
	* @throws IOException In case there was a problem in the communication.
	*/
	void proveCheckCircuits();

	/**
	* Run the verify stage of the diff protocol for each evaluate circuits.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void proveCorrectnessOfPlacementMasks();

public:
	/**
	* Constructor that sets the parameters and creates the commitment objects.
	* @param execution Contains parameters regarding the execution.
	* @param primitives Contains primitives to use in the protocol.
	* @param channel The channel that communicates between the parties.
	* @param bundleBuilders Contains the circuit parameters and used to build the circuit.
	*/
	CutAndChooseProver(const shared_ptr<ExecutionParameters> & execution, vector<shared_ptr<CommParty>> & channels, vector<shared_ptr<BundleBuilder>> & bundleBuilders);

	/**
	* Runs the prover execution.
	*
	* Pseudo code:
	*
	* 1. Garble the circuits
	* 2. Receive commitment to cut and choose
	* 3. Send the garbled circuits
	* 4. Send commitments on the keys
	* 5. Receive cut and choose challenge
	* 6. prove the checked circuits
	* 7. Put circuits in buckets
	* 8. Prove correctness of placement mask
	*
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void run();

	/**
	* Returns the buckets that include the evaluated circuits.
	*/
	shared_ptr<BucketBundleList> getBuckets();
};
