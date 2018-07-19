#pragma once

#include "../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceParty.hpp"
#include "../../include/CommitmentWithZkProofOfDifference/SC.hpp"
#include "../../include/OfflineOnline/primitives/DecommitmentsPackage.hpp"
#include "../../include/CommitmentWithZkProofOfDifference/DifferenceCommitmentCommitterBundle.hpp"
#include "../../include/CommitmentWithZkProofOfDifference/ProveDiff.hpp"
#include "../../include/primitives/CutAndChooseSelection.hpp"

/**
* This protocol is used in the input consistency check. 
* It reveals the xor of both committed values without revealing the committed values themselves.
* Meaning, given two commitments: Hcom(s) Hcom(s'), we want to reveal s^s' without revealing s and s'.
*
* This class represents the committer of the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class CmtWithDifferenceCommitter : public CmtWithDifferenceParty
{
private:
	size_t n;															//The total number of circuits. (checked + eval)
	vector<shared_ptr<vector<byte>>> x;								//The actual committed values.
	shared_ptr<CmtCCommitmentMsg> wCommitment;						//Commitment on the sigma array.
	shared_ptr<CmtCCommitmentMsg> kCommitment;						//Commitment on the key to the encryption scheme that encrypts the cut and choose selection.
	shared_ptr<SymmetricCiphertext> cutAndChooseSelectionCiphertext;	//The ciphertext of the cut and choose selection.
	long commitmentId = 0;											//id for the commitment scheme. each commitment has its own id.
	vector<shared_ptr<SC>> c;													//Holds the commitment pair for each actual committed value.
	SecretKey k;													//The key to the encryption scheme that encrypts the cut and choose selection.
	vector<byte> w;													//The sigma array received from the receiver.

	/**
	* Commits on the difference of each pair of bundles.
	* @param b1 The first bundle to use.
	* @param b2 The second bundle to use.
	* @param index The index in the difference package.
	* @param msg The package to put the cmmitments.
	*/
	void commitToDifference(DifferenceCommitmentCommitterBundle& b1, DifferenceCommitmentCommitterBundle& b2, size_t index, ProveDiff& msg);

	/**
	* Receives w from the receiver and verifies it.<P>
	* W is the sigma array used to get the decommitments.
	* @throws IOException In case of a problem during the communication.
	*/
	void receiveW(); 

	 /**
	 * Gets the decommitments of the differences according to the received w (sigma array).
	 * @param b1  The first bundle to use.
	 * @param b2  The second bundle to use.
	 * @param decommitments An array to store the decommitments.
	 * @param index The index to use in order to store the decommitments.
	 */
	void proveDifference(DifferenceCommitmentCommitterBundle & b1, DifferenceCommitmentCommitterBundle & b2, vector<byte> & decommitmentsX, vector<byte> & decommitmentsR, size_t index);

public:
	/**
	* A constructor that sets the given parameters and initialize them.
	* @param x The actual committed values.
	* @param numCircuits The total number of circuits. (checked + eval)
	* @param statisticalParameter Indicates how much commitments pairs will be.
	* @param channel Used to communicate between the parties.
	* @param random Used to initialize the commitment scheme.
	* @param hash Used in the commitment scheme.
	*/
	CmtWithDifferenceCommitter(vector<shared_ptr<vector<byte>>> &x, int numCircuits, int statisticalParameter, 
		shared_ptr<CommParty> channel, shared_ptr<CryptographicHash> hash);

	/**
	* The setup phase of the protocol. Receives from the receiver the wCommitment, kCommitment and cutAndChooseSelectionCiphertext.
	* @throws IOException In case of a problem during the receiving.
	*/
	void setup();

	/**
	* Creates all commitment pairs for all secrets and puts the created commitments in a big array
	* @return an array contains all created commitments.
	*/
	vector<vector<vector<byte>>> getCommitments();

	/**
	* Receives the cut and choose selection according to the following steps:
	* 1. Receive kDecommitment, verifies it.
	* 2. If not verified, throw a cheating exception.
	* 3. If verified, convert the committed value into a key.
	* 4. Decrypt the cutAndChooseSelectionCiphertext to get the cut and choose selection.
	* @return The cut and choose selection, if everything went good.
	* @throws IOException In case of a problem during the communication.
	* @throws CheatAttemptException If the received kDecommitment was not verified.
	*/
	//TODO **** CHECKUP - someone call this?? CutAndChooseSelection receiveCutAndChooseSelection();

	/**
	* Puts in the given package the required secret, all randoms for this secret and all decommitments objects.
	* @param k The index of the required secret.
	* @param counter The placed in the package were the secret, randoms and secommitments should be placed.
	* @param pack The package that will be sent to the other party and should be filled woth the secret, randoms and decryptions.
	*/
	void getDecommit(int index, int counter, DecommitmentsPackage& pack);

	/**
	* Returns a DifferenceCommitmentCommitterBundle that contains some data of this protocol.
	* @param k The index of the required secret and related commitments.
	*/
	shared_ptr<DifferenceCommitmentCommitterBundle> getBundle(size_t index);

	/**
	* Proves the difference by committing to the difference of each pair of bundles, receive w and than send the decommitments of the differences.
	* @param bucket Contains the DifferenceCommitmentCommitterBundle to prove.
	* @throws IOException
	* @throws ClassNotFoundException
	*/
	void proveDifferencesBetweenMasks(vector<shared_ptr<DifferenceCommitmentCommitterBundle>>& bucket);
};
