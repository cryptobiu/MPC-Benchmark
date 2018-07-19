#pragma once

#include "../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceParty.hpp"
#include "../../include/primitives/CutAndChooseSelection.hpp"
#include "../../include/OfflineOnline/primitives/DecommitmentsPackage.hpp"
#include "../../include/CommitmentWithZkProofOfDifference/DifferenceCommitmentReceiverBundle.hpp"
#include "../../include/CommitmentWithZkProofOfDifference/ProveDiff.hpp"
#include "../primitives/CryptoPrimitives.hpp"
#include "../common/CommonMaliciousYao.hpp"


/**
* This protocol is used in the input consistency check. <p>
* It reveals the xor of both committed values without revealing the committed values themselves.<p>
* Meaning, given two commitments: Hcom(s) Hcom(s'), we want to reveal s^s' without revealing s and s'. <P>
*
* This class represents the receiver of the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class CmtWithDifferenceReceiver : public CmtWithDifferenceParty
{
private:

	//Ids for the w and k commitments.
	static const int COMMIT_LABEL_W = 1;
	static const int COMMIT_LABEL_K = 2;

	shared_ptr<CutAndChooseSelection> selection; 			// Cut and choose selection
	vector<byte> w;						 					//Sigma array.
	SecretKey k;					 			//The key to the encryption scheme that encrypts the cut and choose selection.
	vector<vector<vector<byte>>> c;		//The commitment pair for all secrets.
	vector<shared_ptr<vector<byte>>> receivedDeltas;
	shared_ptr<CmtCDecommitmentMessage> decomW;				//Decommitment on the sigma array.
	shared_ptr<CmtCDecommitmentMessage> decomK;				//Decommitment on the key to the encryption scheme that encrypts the cut and choose selection.
	size_t n;													//Total number of circuits (eval+chacked)

	void verifyDecommitment(CryptographicHash* hash, vector<byte>* commitment, vector<byte> & x, vector<byte> & r, int rOffset, int hashSize, vector<byte> & result);
public:
	/**
	* A constructor that sets the given parameters and initialize them.
	* @param selection The cut and choose selection.
	* @param numCircuits Total number of circuits (eval+chacked)
	* @param statisticalParameter Indicates how much commitments pairs will be.
	* @param channel Used to communicate between the parties.
	* @param random Used to initialize the commitment scheme.
	* @param hash Used in the commitment scheme.
	*/
	CmtWithDifferenceReceiver(shared_ptr<CutAndChooseSelection> selection, int numCircuits, int statisticalParameter,
		const shared_ptr<CommParty> & channel, const shared_ptr<CryptographicHash> & hash);
	
	/**
	* The setup phase of the protocol.<P>
	* Generate CmtCCommitmentMsg from w and k.
	* Generate decommit values for w and k.
	* Send the created CmtCCommitmentMsg to the committer.
	*
	* @throws IOException
	*/
	void setup();

	/**
	* Sets the given commitments.
	* @param commitments The commitments to set.
	*/
	void receiveCommitment(vector<vector<vector<byte>>> & commitments);

	/**
	* Sends the decommitment of the key for the encryption scheme so that the other party can decrypt ccSelection.
	* @throws IOException In case of a problem during the communication.
	*/
	void revealCutAndChooseSelection();

	/**
	* Extracts from the given package the committed value, all randoms used to commit and the decommitment objects.
	* @param k The index of the checked circuit. The decommitments should be verified against the commitments from the k index.
	* @param counter The index of the checked circuit in the selection.
	* @param pack THe package received from the committer that contains the committed value, randoms and decommitments.
	* @return the committed value, if the decommitments were all verified.
	* @throws CheatAttemptException In case there was a decommitment that was not verified.
	*/
	shared_ptr<vector<byte>> receiveDecommitment(size_t index, int counter, DecommitmentsPackage& pack);

	/**
	* Returns a DifferenceCommitmentReceiverBundle that contains some data of this protocol.
	* @param j The index of the required commitment.
	*/
	DifferenceCommitmentReceiverBundle getBundle(int j);

	/**
	* Verifies the difference by receive the difference of each pair of bundles, send w and than verify the decommitments of the differences.
	* @param bucket Contains the DifferenceCommitmentCommitterBundle to verify.
	* @return the committed differences.
	* @throws IOException In case of a problem during the communication.
	* @throws CheatAttemptException In case the verification fails.
	*/
	vector<shared_ptr<vector<byte>>> verifyDifferencesBetweenMasks(vector<shared_ptr<DifferenceCommitmentReceiverBundle>>& bucket);

private:
	/**
	 * Receives the difference of each pair of bundles.
	 * @param index The index in the difference package.
	 * @param msg The package to get the commitments.
	 * @return THe committed differences, if there was no cheating.
	 * @throws CheatAttemptException in case the received committed difference is differ from the calculated one.
	 */
	shared_ptr<vector<byte>> receiveDifference(size_t index, ProveDiff& msg);

	/**
	* Sends the chosen w.
	* @throws IOException
	*/
	void decommitToW();

	/**
	* Verifies the decommitments of the differences according to w (cmtSelection).
	* @param b1 The first bundle of the difference.
	* @param b2 The second bundle of the difference.
	* @param k1 The index to use in order to get the decommitments.
	* @param decommitments An array holds the decommitments.
	* @throws CheatAttemptException
	*/
	void verifyDifference(shared_ptr<DifferenceCommitmentReceiverBundle>& b1, shared_ptr<DifferenceCommitmentReceiverBundle>& b2, size_t k1,
		ProveDecommitments & decommitments);
};