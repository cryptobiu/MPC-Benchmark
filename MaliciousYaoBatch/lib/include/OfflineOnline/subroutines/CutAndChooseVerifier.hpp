#pragma once

#include <libscapi/include/comm/Comm.hpp>
#include "../../../include/primitives/ExecutionParameters.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/OfflineOnline/primitives/BundleBuilder.hpp"
#include "../../../include/primitives/CutAndChooseSelection.hpp"
#include "../../../include/OfflineOnline/primitives/BucketLimitedBundleList.hpp"
#include "../../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceReceiver.hpp"
#include "../../../include/OfflineOnline/primitives/DecommitmentsPackage.hpp"
#include "../../../include/OfflineOnline/primitives/CheatingRecoveryBundleBuilder.hpp"
#include "../../common/LogTimer.hpp"
#include <sys/types.h>

/**
* This is the Cut And Choose verifier used in the protocol.
*
* The cut and choose paradigm is an important building block in the offline/online Yao protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class CutAndChooseVerifier
{
private:
	/**
	* The following attributes are needed to the prover execution.
	*/
	const static int COMMIT_ID_CUT_AND_CHOOSE = 1;
	const static int COMMIT_ID_BUCKET_MAPPING = 2;

	shared_ptr<ExecutionParameters> execution;			//Contains parameters regarding the execution. 
	vector<shared_ptr<CommParty>> channel;						// The channel that communicates between the parties.
	shared_ptr<BundleBuilder> bundleBuilder;			// Contains the circuit parameters used to build the circuit.
	shared_ptr<CutAndChooseSelection> selection;		// Indicates for each circuit if it is a checked circuit or evaluated circuit.
	shared_ptr<BucketMapping> bucketMapping;			//The object that used in order to randomly map the circuits into buckets.
	vector<byte> seedMapping;							//Seed to the above mapping algorithm.
	int numCircuits;
	CmtCommitter* cmtSender;							//Used to commit and decommit during the protocol.
	CmtSimpleHashReceiver* cmtReceiver;					//Used to receive the commitment and decommitment from the cut and choose prover. 

	vector<block*> garbledTables;						//Will hold the garbled table of each circuit.
	vector<size_t> garbledTablesSize;						//Will hold the garbled table size of each circuit.
	vector<vector<byte>> translationTables;				//Will hold the translation table of each circuit.
	string filePrefix;

	/*
	* wires' indices.
	*/
	size_t labelsXSize;
	size_t labelsY2Size;
	size_t outputLabelsSize;

	/*
	* Commitment used in the protocol: includes commitments on seeds, masks, keys.
	*/
	vector<shared_ptr<CmtCCommitmentMsg>> commitmentToSeed;
	vector<shared_ptr<CmtCCommitmentMsg>> commitmentToCommitmentMask;
	vector<shared_ptr<CommitmentBundle>> commitmentsX;
	vector<shared_ptr<CommitmentBundle>> commitmentsY1Extended;
	vector<shared_ptr<CommitmentBundle>> commitmentsY2;
	vector<shared_ptr<CmtCCommitmentMsg>> commitmentsOutput;
	vector<shared_ptr<CmtCDecommitmentMessage>> decommitmentsOutput;

	//This protocol and its related bundles are used in the input consistency check.
	vector<shared_ptr<DifferenceCommitmentReceiverBundle>> diffCommitments;
	shared_ptr<CmtWithDifferenceReceiver> diffProtocol;

	shared_ptr<BucketLimitedBundleList> buckets;			//Will hold the circuits according to the mapping algorithm.

	void receiveCircuit(int from, int to, int threadIndex);
public:
	/**
	* Constructor that sets the parameters and creates the commitment objects.
	* @param execution Contains parameters regarding the execution.
	* @param primitives Contains primitives to use in the protocol.
	* @param channel The channel that communicates between the parties.
	* @param bundleBuilders Contains the circuit parameters and used to build the circuit.
	* @param inputLabelsY2 The input wires' indices of p2. Sometimes these indices are not the same as in the given circuit.
	*/
	CutAndChooseVerifier(const shared_ptr<ExecutionParameters> & execution, vector<shared_ptr<CommParty>> & channel,
		const shared_ptr<BundleBuilder> & bundleBuilder, string filePrefix, int labelsY2Size = 0 );

	~CutAndChooseVerifier(){
		delete cmtSender;
		delete cmtReceiver;
	}

	/**
	* Run the verifier execution.
	*
	* Pseudo code:
	*
	* 1. Send to the cut and choose prover the commitments on the circuit selection and mapping.
	* 2. Receive the garbled circuits
	* 4. Receive commitments on the keys
	* 5. Send the cut and choose challenge
	* 6. verify the checked circuits
	* 7. Put circuits in buckets
	* 8. verify correctness of placement mask
	*
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void run(); 

	/**
	 * Returns the buckets that include the evaluated circuits.
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	shared_ptr<BucketLimitedBundleList> getBuckets();

private:
	/**
	* Put the evaluated circuits in buckets, according to the mapping algorithm received from the cut and choose verifier.
	* @throws IOException
	* @throws FileNotFoundException
	*/
	void putCircuitsInBuckets();

	/**
	* Selects the checked circuit and the evaluated circuits.
	* @return The selection object that contains the circuits selection.
	*/
	void selectCutAndChoose(int selectionSize);

	/**
	* Commits on the circuit selection and the circuit mapping.
	* @throws IOException In case of a problem during the communication.
	*/
	void commitToCutAndChoose();


	/**
	* Receive the garbled tables and translation table of all circuits.
	* @throws CheatAttemptException
	* @throws IOException
	*/
	void receiveGarbledCircuits();

	/**
	* Receive from the cut and choose prover the commitments (on seeds, masks, keys, etc) of each circuit.
	* @throws CheatAttemptException
	* @throws IOException
	*/
	void receiveCommitments();

	/**
	* Send to the cut and choose prover the decommitments on the circuit selection and mapping.
	* @throws IOException
	* @throws CheatAttemptException In case of problem during the decommiting.
	*/
	void revealCutAndChoose();

	/**
	* Verify the checked circuit by verifying the commitments on the seed, masks and keys.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void verifyCheckCircuits();

	/**
	* Run the verify stage of the diff protocol for each evaluate circuits.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	void verifyCorrectnessOfPlacementMasks();
};
