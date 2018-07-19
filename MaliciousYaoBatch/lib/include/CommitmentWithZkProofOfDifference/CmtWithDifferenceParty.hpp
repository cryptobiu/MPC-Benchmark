#pragma once

#include <libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp>
#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/primitives/Prf.hpp>
#include <libscapi/include/primitives/HashOpenSSL.hpp>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>
#include <libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp>



/**
* This class is an abstract class the gather parameters that common for the committer and verifier of the difference
* protocol in the input consistency protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class CmtWithDifferenceParty
{
protected:
	int numCircuits;							//The total number of circuits. (checked + eval)
	int s;										//Security parameter. Indicates how much commitments pairs will be.
	shared_ptr<CmtCommitter> cmtSender;			//The committer in the commitment scheme.
	shared_ptr<CmtReceiver> cmtReceiver;		//The receiver in the commitment scheme.
	shared_ptr<CommParty> channel;				//Used to communicate between the channels.
	shared_ptr<SymmetricEnc> enc;				//Used to encrypt and decrypt the cut and choose selection.

	/**
	* Initializes the commitment scheme using the given parameters.
	* @param channel  Used to communicate between the parties.
	* @param hash The hash function to use in the commitment.
	* @throws IllegalArgumentException
	*/
	void initCommitmentScheme(shared_ptr<CommParty> channelCom, shared_ptr<CryptographicHash> hash);

public:
	/**
	* A constructor that sets the parameters and initialize the encryption scheme.
	* @param numCircuits The total number of circuits. (checked + eval)
	* @param statisticalParameter A security parameter. Indicates how much commitments pairs will be.
	* @param channel Used to communicate between the channels.
	* @param random Source of randomness to use.
	* @throws IllegalArgumentException In case numCircuits == 0
	*/
	CmtWithDifferenceParty(int numCircuits, int statisticalParameter, const shared_ptr<CommParty> & channel);
};