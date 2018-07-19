#pragma once

#include <libscapi/include/interactive_mid_protocols/CommitmentScheme.hpp>
#include "../../include/common/CommonMaliciousYao.hpp"
#include "../primitives/CryptoPrimitives.hpp"

/**
* This class represents one commitment in the difference protocol. 
* Each commitment contains commitment message on the random value r and the xor of r and the message x. 
* It also contain the decommitments of the above commitments.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class SCom {
private:
	vector<byte> c0;			//commitment on x xor r.
	vector<byte> c1;			//commitment on r.		
	vector<byte> d0;			//original x xor r.
	vector<byte> d1;			//original r.
	vector<byte> r0;			//random used to commit x xor r.
	vector<byte> r1;			//random used to commit r.

	void commit(PrgFromOpenSSLAES* prg, CryptographicHash* hash, vector<byte> & val, vector<byte> &r, vector<byte> & result);
public:

	SCom() {}

	/**
	* A constructor that computes the commitment and decommitment messages of x xor r and r.
	* @param committer Used to commit and decommit the values.
	* @param x The actual value to commit on.
	* @param r The random value used to commit.
	* @param id The first id to use in the commitment.
	* @throws CommitValueException if the given committer cannot commit on a byte[].
	*/
	SCom(PrgFromOpenSSLAES* prg, vector<byte>& x, vector<byte>& r, long id);

	/**
	* Returns the commitment message of x^r.
	*/
	vector<byte> getC0() { return this->c0; }

	/**
	* Returns the commitment message of r.
	*/
	vector<byte> getC1() { return this->c1; }

	/**
	* Returns the decommitment message of r or x^r according to the given index.
	* @param i Indicates which decommitment to return.
			If i==0, return the decommitment on x^r.
			Else, return the decommitment on r.
	*/
	vector<byte> getDecomX(int i) { return (i == 0) ? this->d0 : this->d1; }
	vector<byte> getDecomR(int i) { return (i == 0) ? this->r0 : this->r1; }

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & c0;
		ar & c1;
		ar & r0;
		ar & r1;
		ar & d0;
		ar & d1;
	}
};