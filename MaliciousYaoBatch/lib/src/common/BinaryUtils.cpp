#include "../../include/common/BinaryUtils.hpp"

shared_ptr<vector<byte>> BinaryUtils::getBinaryByteArray(vector<byte> &bytes)
{
	auto size = sizeof(byte) * 8;
	size_t numBits = size*bytes.size();
	shared_ptr<vector<byte>> binary = make_shared<vector<byte>>(numBits);
	// Mask the entire value up to this bit.
	int mask = 0x80;

	for (size_t i = 0; i < numBits; i++)
	{
		// Take the byte the current bit belongs to.
		byte currentByte = bytes[i / size];
		// Shift by the current bit's index within the byte.
		int shiftBy = i % size;
		// If the bit is zero the entire value will be zero.
		// Cast the result back to byte (numbers are int by default).
		binary->at(i) = (byte)((currentByte << shiftBy & mask) == 0 ? 0 : 1);
	}

	return binary;
}

block* BinaryUtils::xorBlockArray(block* k1, int size1, block* k2, int size2)
{
	//Check that the lengths are equal.
	if (size1 != size2) {
		throw InvalidInputException("BinaryUtils::xorBlockVector - vectors not the same size");
	}

	//Xor each byte.
	block* result = (block *)_mm_malloc(sizeof(block) * size1, SIZE_OF_BLOCK);

	for (size_t i = 0; i < size1; i++) {
		result[i] = _mm_xor_si128(k1[i], k2[i]);
	}
	return result;
}

void BinaryUtils::xorBlockVectorInPlace(vec_block_align & k1, vec_block_align & k2, vec_block_align & toVec)
{
	//make sure there is space for the xor
	if (k1.size() > toVec.size()) {
		throw InvalidInputException("BinaryUtils::xorBlockVectorInPlace - toVec is to small");
	}

	//Check that the lengths are equal.
	if (k1.size() != k2.size()) {
		throw InvalidInputException("BinaryUtils::xorBlockVectorInPlace - vectors not the same size");
	}

	//Xor each byte.
	size_t size = k1.size();

	for (size_t i = 0; i < size; i++) {
		toVec[i] = _mm_xor_si128(k1[i], k2[i]);
	}
}

bool BinaryUtils::equalBlocks(block a, block b) {
	//A function that checks if two blocks are equal by casting to double size long array and check each half of a block
	long *ap = (long*)&a;
	long *bp = (long*)&b;
	if ((ap[0] == bp[0]) && (ap[1] == bp[1]))
		return 1;
	else {
		return 0;
	}
}

vector<byte> BinaryUtils::xorArrays(vector<byte> k1, vector<byte> k2) {
	//Check that the lengths are equal.
	size_t size = k1.size();
	if (size != k2.size()) {
		throw InvalidInputException("BinaryUtils::xorArrays - vectors not the same size");
	}

	vector<byte> result(size);

	//Xor each byte.
	for (size_t i = 0; i < size; i++) {
		result[i] = k1[i] ^ k2[i];
	}
	return result;
}

bool BinaryUtils::checkEquals(vector<byte> array1, vector<byte> array2) {
	size_t size = array1.size();
	if (size != array2.size()) return false;
	for (size_t i = 0; i < size; i++) {
		if (array1[i] != array2[i]) return false;
	}
	return true;
}