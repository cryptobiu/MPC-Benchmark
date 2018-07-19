#pragma once

#ifndef common_malicious_yao
#define common_maliciou_yao

#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>
#include <bitset>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/export.hpp>
#include <boost/serialization/split_member.hpp>

#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
#include <libscapi/include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp>
#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/primitives/Prg.hpp>

#include "../../include/common/aligned_allocator.hpp"
#include "../../include/common/aligned_allocator_no_destructor.hpp"


typedef unsigned char byte;

typedef __m128i block;

typedef vector<byte, aligned_allocator<byte, SIZE_OF_BLOCK>> vec_byte_align;

typedef vector<block, aligned_allocator<block, SIZE_OF_BLOCK>> vec_block_align;

#define SIZE_OF_BLOCK 16 //size in bytes

#define KEY_SIZE 128 //The number of bits in the key. It is currently set to 128, and the {@code FIXED_KEY} field is this size.

#ifdef _WIN32
#else
#include <libscapi/include/circuits/Compat.h>
#endif

using namespace std;

/*
* For deleting block* in unique_ptr
*/
struct aligned_free {
	void operator()(void* p) {
		_aligned_free(p);
	}
};


/********************************************
Common functions for MaliciousYao protocol
*********************************************/

/*
Basic function that take vector and make it in to a string with separator char between every element.
*/
template <typename T>
string vectorToString(const vector<T>& vec, const string separator)
{
	std::ostringstream oss;

	if (!vec.empty()) {
		// Convert all but the last element to avoid a trailing separator
		auto sepOss = std::ostream_iterator<T>(oss, separator.c_str());
		std::copy(vec.begin(), vec.end() - 1, sepOss);

		// Now add the last element with no delimiter
		oss << vec.back();
	}
	else {
		oss << "";
	}

	return oss.str();
}


template <typename T>
string vectorToString(const vector<T>* vec, const string separator)
{
	std::ostringstream oss;

	if (!vec->empty()) {
		// Convert all but the last element to avoid a trailing " "
		std::copy(vec->begin(), vec->end() - 1,
			std::ostream_iterator<T>(oss, separator.c_str()));

		// Now add the last element with no delimiter
		oss << vec->back();
	}
	else {
		oss << "";
	}

	return oss.str();
}

/**
Returns the input indices of the given party in the given circuit.
Inputs:
bc The boolean circuit to get the input indices of.
party The number of the party we want his input indices.
*/
vector<int> circuitGetLabels(GarbledBooleanCircuit* gbc, int party);

/*
Get vector on stack and copy to new vector on heap.
Return shared_ptr to the new vector
*/
template <typename T>
shared_ptr<vector<T>> copyVectorToSharedPtr(vector<T> & vec)
{
	shared_ptr<vector<T>> arr(new vector<T>(vec.size()));

	copy(vec.begin(), vec.end(), inserter(*arr.get(), arr->begin()));

	return arr;
}

/*
Make vector of random bits, save as bytes.
inputs:
random generator
vector size
*/
void makeRandomBitByteVector(PrgFromOpenSSLAES* prg, vector<byte> & vec);
/*
Make random bit, as byte.
inputs:
random generator
*/
byte getRandomBit(PrgFromOpenSSLAES* prg);

/*
Read string that was made with vectorToString() to vector<byte>
*/
vector<byte> readByteVectorFromString(string str, const char separator);

/*
Read string that was made with vectorToString() to vector<long>
*/
vector<long> readLongVectorFromString(string str, const char separator);

/*
Read string that was made with vectorToString() to vector<int>
*/
vector<int> readIntVectorFromString(string str, const char separator);

/*
Read string that was made with vectorToString() to vector<string>
*/
vector<string> readStringVectorFromString(string str, const char separator);


/*
Class VecBlock save block* align and size
*/
class VecBlock {
	block* blockArray = NULL;
	size_t size;

public:
	/*
	Create block* aligned to block size (16) in given size.
	*/
	VecBlock(unsigned int num) {
		this->size = num;
		this->blockArray = (block *)_mm_malloc(sizeof(block) * num, SIZE_OF_BLOCK);
	}

	~VecBlock() {
		//_aligned_free(this->blockArray);
		_mm_free(this->blockArray);
	}
	/*
	Create block* from vector of bytes
	*/
	VecBlock(vector<byte>& vec) {
		this->size = vec.size();
		this->blockArray = (block *)_mm_malloc(sizeof(block) * this->size, SIZE_OF_BLOCK);
		//copy bytes to block
		memcpy(this->blockArray, &vec[0], sizeof(block) * this->size);
	}

	block* getBlock() { return this->blockArray; }
	size_t getSize() { return this->size; }

	void setBlock(block* newBlock, unsigned int newSize) {
		if (blockArray != NULL) {
			_aligned_free(this->blockArray);
		}

		this->blockArray = newBlock;
		this->size = newSize;
	}

	block& operator[](std::size_t idx) { return this->blockArray[idx]; }
};

//A function that checks if two blocks are equal by casting to double size long array and check each half of a block
bool equalBlocks(block &a, block &b);

/*
* A function that checks if two blocks array are equal.
* Assume same size for both arrays.
*/
bool equalBlocksArray(block* a, block* b, size_t size);

/*
Take vector of bytes and set it to new vector block aligned to block size.
*/
vec_block_align convertByteVectorToBlockVectorAligned(vector<byte> &vec);

/*
Take vector of blocks and set it to new vector bytes.
*/
vector<byte> convertBlockVectorAligneToByteVector(vec_block_align &vec);

block* convertByteVectorToBlockArray(vector<byte>* vec);

vector<byte> convertBlockArrayToByteVector(block* vec, int size);

/*
 Get vector<block> align and set to vector<byte> from byte*
 The block vector has the distractor, not the byte vector!
*/
void makeByteVectorFromBlockVector(vec_block_align &vec, vector<byte> & toRet);


/***********************************************************************
			Write and Read function (using cereal)
************************************************************************/
//const string TEMP_FILE = "tempFile";
//
//vector<byte> readFileToBuffer(const string& fileName);
//
//void writeToFileFromBuffer(vector<byte>& buffer, const string& fileName);

/*
 boost serialize need to register classes inherit from abstract class
*/
template<class Archive>
void registerSerialize(Archive & ar)
{
	ar.template register_type<CmtSimpleHashCommitmentMessage>();
	ar.template register_type<CmtSimpleHashDecommitmentMessage>();
	ar.template register_type<ByteArraySymCiphertext>();
	ar.template register_type<IVCiphertext>();
}

#define NUMBER_OPEN_TRY 10

template<class toArchive>
void sendSerialize(toArchive& obj, CommParty* commParty)
{
	//new scop - serialize need to flush
	std::stringstream os(std::ios::binary | ios::out | ios::in);
	{
		boost::archive::binary_oarchive oa(os);
		registerSerialize(oa);
		oa << obj;
	}

	commParty->writeWithSize((const byte*)os.str().data(), os.str().length());

}

template<class fromArchive>
void readSerialize(fromArchive& obj, CommParty* commParty)
{
	int size = commParty->readSize();
	vector<byte> buffer(size);
	commParty->read(&buffer[0], size);
	{
		std::stringstream is(std::string(&buffer[0], &buffer[0] + size), std::ios::binary | ios::out | ios::in);
		//read file and set obj
		boost::archive::binary_iarchive ia(is);
		registerSerialize(ia);
		ia >> obj;
	}
}

/**
* Enum structure that defines possible outputs of circuit evaluation. <P>
* The outputs of multiple circuits computations can be equal to each other or vary.
* VALID_OUTPUT is the case when all circuits output the same result.
* INVALID_WIRE_FOUND is the case when there is a problem during the output processing.
* FOUND_PROOF_OF_CHEATING is the case when there is at least one output that differs from the other output values.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
enum CircuitEvaluationResult {
	VALID_OUTPUT, 				// All circuits output the same result.
	INVALID_WIRE_FOUND, 		// There was a problem during the output processing.
	FOUND_PROOF_OF_CHEATING		// There is at least one output that differs from the other output values.

};
/**********************************************************************/

#endif // !common_malicious_yao
