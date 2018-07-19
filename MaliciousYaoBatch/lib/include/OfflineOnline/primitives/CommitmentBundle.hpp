#pragma once

#include <libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>
#include <libscapi/include/infra/Common.hpp>
#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/common/KeyUtils.hpp"

#include <boost/format.hpp>

/**
 A CommitmentBundle is a struct that holds the parameters pf the commitments on the keys. 

 These parameters are the commitements of all keys, decommitments and the wires indices. 

 The bundle is used during the offline and the online phases of the protocol.
*/
class CommitmentBundle {
private:
	shared_ptr<vector<byte>> commitments;
	vector<long> commitmentIds;
	shared_ptr<vector<byte>> decommitments;
	shared_ptr<vector<byte>> decommitmentRandoms;

	int commitmentSize = CryptoPrimitives::getHash()->getHashedMsgSize();
	int keySize = 16;

	void doConstruct(PrgFromOpenSSLAES* random, CryptographicHash* hash, int keyLength, vec_block_align& wires, size_t labelsSize, vector<byte>& commitmentMask, vector<byte>& placementMask);
	void calcCommitment(PrgFromOpenSSLAES* prg, vector<byte> & r, CryptographicHash* hash, vector<byte> & value, long id, int i, int k);
	
public:

	CommitmentBundle(){}

	/**
	 A constructor that sets the given arguments.
	 Inputs:
		 labels The wires' indices.
		 commitments Commitments on all wires' keys.
		 decommitments Decommitments on all wires' keys.
	*/
	CommitmentBundle(const shared_ptr<vector<byte>> & commitmentsVec, vector<long>& commitmentsIdsVec, const shared_ptr<vector<byte>> & decommitmentsVec, const shared_ptr<vector<byte>> & decommitmentRandomsVec);

	 /**
	  A constructor that sets the given arguments.
	  Inputs:
		 labels The wires' indices.
		 commitments Commitments on all wires' keys.
	 */
	CommitmentBundle(const shared_ptr<vector<byte>> & commitments, vector<long>& commitmentIds) : CommitmentBundle(commitments, commitmentIds, nullptr, nullptr) {}

	 /*
	   A constructor to replace CommitmentBundleBuilder
	   * @param primitives Contains the primitives objects to use.
	   * @param channel Used to communicates between the parties.
	   * @param keyLength The size of each key, in bytes.
	   * @param wires both keys of each wire.
	   * @param labels wires' indices.
	   * @param commitmentMask
	   * @param placementMask
	 */
	 CommitmentBundle(PrgFromOpenSSLAES* random, CryptographicHash* hash, int keyLength, vec_block_align& wires, size_t labelsSize,
		 vector<byte>& commitmentMask, vector<byte>& placementMask) {
		 doConstruct(random, hash, keyLength, wires, labelsSize, commitmentMask, placementMask);
	 }

	 /*
	 A constructor to replace CommitmentBundleBuilder
	 * @param primitives Contains the primitives objects to use.
	 * @param channel Used to communicates between the parties.
	 * @param keyLength The size of each key, in bytes.
	 * @param wires both keys of each wire.
	 * @param labels wires' indices.
	 * @param commitmentMask
	 */
	 CommitmentBundle(PrgFromOpenSSLAES* random, CryptographicHash* hash, int keyLength, vec_block_align& wires, size_t labelsSize, vector<byte>& commitmentMask) {
		 vector<byte> placementMask;
		 doConstruct(random, hash, keyLength, wires, labelsSize, commitmentMask, placementMask);
	 } 

	 /**
	  Returns the commitment that matches the given sigma of the given wire index.
	  Inputs:
		 wireIndex The index of the wire to get the commitment on.
		 sigma A boolean that indicates which commitment to return.
	 */
	 CmtSimpleHashCommitmentMessage getCommitment(size_t wireIndex, int sigma) const;

	 /**
	  Returns the decommitment that matches the given sigma of the given wire index.
	  Inputs:
		 wireIndex The index of the wire to get the decommitment on.
		 sigma A boolean that indicates which decommitment to return.
	 */
	CmtSimpleHashDecommitmentMessage getDecommitment(size_t wireIndex, int sigma);
	shared_ptr<vector<byte>> getDecommitmentsX() { return decommitments; }
	shared_ptr<vector<byte>> getDecommitmentsRandoms() { return decommitmentRandoms; }

	shared_ptr<vector<byte>> getCommitments() { return commitments; }
	vector<long>& getCommitmentsIds() { return commitmentIds; }

	 /**
	  Verifies that this commitment bundle and the given one are equal.
	  Input:
		 other Another CommitmentBundle to check equality.
	  @throws CheatAttemptException in case the given bundle is different than this one.
	 */
	 bool operator==(const CommitmentBundle& b);

	 friend class boost::serialization::access;
	 template<class Archive>
	 void serialize(Archive & ar, const unsigned int version)
	 {
		 ar & commitments;
		 ar & commitmentIds;
		 ar & decommitments;
		 ar & decommitmentRandoms;
	 }
};