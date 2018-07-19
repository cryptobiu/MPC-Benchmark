#include "../../include/CommitmentWithZkProofOfDifference/CmtWithDifferenceParty.hpp"
#include "../../include/primitives/CryptoPrimitives.hpp"

void CmtWithDifferenceParty::initCommitmentScheme(shared_ptr<CommParty> channelCom, shared_ptr<CryptographicHash> hash)
{
	this->cmtSender = make_shared<CmtSimpleHashCommitter>(channelCom, CryptoPrimitives::getRandom(), hash, hash->getHashedMsgSize());
	this->cmtReceiver = make_shared<CmtSimpleHashReceiver>(channelCom, hash, hash->getHashedMsgSize());

}

CmtWithDifferenceParty::CmtWithDifferenceParty(int numCircuits, int statisticalParameter, const shared_ptr<CommParty> & channel)
{
	//Sets the parameters and initialize the encryption scheme.:
	this->numCircuits = numCircuits;
	if (numCircuits == 0)
	{
		throw invalid_argument("x must contain at least one string!");
	}

	this->s = statisticalParameter;
	this->channel = channel;


	//Initialize the encryption scheme.
	//Use the created prp in order to create an encryption scheme.
	this->enc = make_shared<OpenSSLCTREncRandomIV>("AES");
}
