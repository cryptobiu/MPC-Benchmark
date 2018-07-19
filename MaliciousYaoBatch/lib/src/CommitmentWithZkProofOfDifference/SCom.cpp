#include "../../include/CommitmentWithZkProofOfDifference/SCom.hpp"

SCom::SCom(PrgFromOpenSSLAES* prg, vector<byte>& x, vector<byte>& r, long id)
{
	//Check that the length of the given arrays are equal.
	assert(x.size() == r.size());

	size_t size = x.size();
	//Xor x and r.
	d0.resize(size);
	for (size_t i = 0; i < size; i++) {
		d0[i] = (byte)(x[i] ^ r[i]);
	}

	d1 = r;

	auto hash = CryptoPrimitives::getHash().get();

	//Get the commitment messages of r and x^r.
	commit(prg, hash, d0, r0, c0);
	commit(prg, hash, d1, r1, c1);
}

void SCom::commit(PrgFromOpenSSLAES* prg, CryptographicHash* hash, vector<byte> & val, vector<byte> &r, vector<byte> & result) {
	//Sample random byte array r
	prg->getPRGBytes(r, 0, hash->getHashedMsgSize());

	//Compute the hash function
	hash->update(r, 0, r.size());
	hash->update(val, 0, val.size());
	hash->hashFinal(result, 0);
}
