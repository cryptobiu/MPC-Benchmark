#pragma once

#include <libscapi/include/circuits/BooleanCircuits.hpp>
#include "../../include/common/CommonMaliciousYao.hpp"

/**
* This class provides some binary utilities to use in the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
*
*/
class BinaryUtils
{
public:
	/**
	* Returns a byte array that is the binary representation of the given byte[].
	* @param bytes array to get the binary representation of.
	*/
	static shared_ptr<vector<byte>> getBinaryByteArray(vector<byte> &bytes);

	/**
	* Returns the result of the XOR of given arrays.
	* @param k1
	* @param k2
	* @throws InvalidInputException
	*/
	static block* xorBlockArray(block* k1, int size1, block* k2, int size2);
	
	/*
	 Xor the given k1 & k2 vectors and put in toVec.
	*/
	static void xorBlockVectorInPlace(vec_block_align &k1, vec_block_align &k2, vec_block_align &toVec);

	static bool equalBlocks(block a, block b);

	static vector<byte> xorArrays(vector<byte> k1, vector<byte> k2);

	static bool checkEquals(vector<byte> array1, vector<byte> array2);
};