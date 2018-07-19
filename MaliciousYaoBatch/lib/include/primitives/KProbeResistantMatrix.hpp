#pragma once

#ifndef NTL_to_KProbeResistantMatrix
#define NTL_to_KProbeResistantMatrix
#include <NTL/GF2.h>
#include <NTL/GF2X.h>
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/GF2EX.h>
#endif

#include <math.h> 

#include <boost/range/irange.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>
#include <libscapi/include/primitives/Prf.hpp>
#include <libscapi/include/cryptoInfra/Key.hpp>

#include "../../include/primitives/CircuitInput.hpp"
#include "CryptoPrimitives.hpp"


/**
* This class represents the K probe-resistant matrix that described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for
* Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, Definition 2.1. 
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class KProbeResistantMatrix
{
private:

	byte* matrix;	//The K probe-resistant matrix.
	size_t n;							//Number of matrix's rows.
	size_t m;							//Number of matrix's columns.

	void allocateKeys(vec_block_align & probeResistantKeys, block &originalKey0, block &originalKey1, size_t i, block &newKey);

	//int getNumberOfShares(size_t i, vec_block_align &probeResistantKeys, int* shares, size_t* lastShare);

	/**
	* Native function that builds the matrix.
	* @return the created matrix.
	*/
	void createMatrix(int K, int N, int t);

	void calculate_k_resistant_matrix_row(int index, int K, int N, int t);

	NTL::GF2E int_to_GF2E(int num);

	/**
	* Calculates the matrix dimensions, see "Offline/Online Setting with Security /for Malicious Adversaries"
	* paper by Yehuda Lindell and Ben Riva, Appendix D.
	*/
	void calculateDimensions(int k, int &t, int &K, int &N);

	/**
	* Returns true if the value of t is too large for the computation.
	*/
	bool tIsToLarge(int t, int k);

	void restoreKeysByRow(block* receivedKeys, block* restoredKeysArray, int from, int to);

public:
	KProbeResistantMatrix(){}

	/**
	 A constructor that sets the given matrix.
	*/
	KProbeResistantMatrix(byte* newMatrix, int n, int m);

	/*
	 A constructor to replace KProbeResistantMatrixBuilder
	 * @param n Rows number of the matrix.
	 * @param k Security parameter.
	*/
	KProbeResistantMatrix(int n, int k);

	~KProbeResistantMatrix() { 
		delete[] matrix;
	}

	/**
	 Returns the probe resistant input size (the matrix columns).
	*/
	size_t getProbeResistantInputSize() {	return m; }

	/**
	 Returns vector of size m, when each cell i contains "i".
	*/
	vector<int> getProbeResistantLabels();

	/**
	 Gets a original keys and transform them into keys that corresponds to the matrix.
	 Inputs:
		 originalKeys The keys that matched the rows of the matrix.
		 mes used to generate new keys.
	 Return
		 the transformed keys, that matched the columns of the matrix.
	*/
	void transformKeys(vec_block_align &originalKeys, AES* mes, vec_block_align& keys);

	/**
	 Gets a original inputs and transform them into inputs that corresponds to the matrix columns.
	 Inputs:
		 originalInput The inputs that matched the rows of the matrix.
		 random used to generate new inputs.
	 Returns:
		 the transformed inputs, that matched the columns of the matrix.
	*/
	CircuitInput* transformInput(const CircuitInput& originalInput, PrgFromOpenSSLAES* random);

	/**
	 Restores the original keys using the matrix from the transformed keys.
	 Input:
		 receivedKeys the transformed keys.
	 Return:
		 the original restored keys.
	*/
	block* restoreKeys(block* receivedKeys, int size, int & returnSize);

	/**
	 Saves the matrix to a file.
	 Inputs:
		 matrix The matrix to write to the file.
		 filename The name of the file to write the matrix to.
	*/
	void saveToFile(string filename);

	/**
	 Loads the matrix from a file.
	 Input:
		 filename The name of the file to read the matrix from.
	 Return:
		 The read matrix.
	*/
	void loadFromFile(string filename);


	/*friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & n;
		ar & m;
		ar & matrix;
	}*/

	// This method lets cereal know which data members to save to file
	friend class boost::serialization::access;
	template<class Archive>
	void save(Archive & ar, const unsigned int version) const;

	// This method lets cereal know which data members to load to file
	template<class Archive>
	void load(Archive & ar, const unsigned int version);

	BOOST_SERIALIZATION_SPLIT_MEMBER()
};

template<class Archive>
inline void KProbeResistantMatrix::save(Archive & ar, const unsigned int version) const
{
	ar << n << m;
	for (int i = 0; i < n*m; i++)
		ar << matrix[i];
	
}

template<class Archive>
inline void KProbeResistantMatrix::load(Archive & ar, const unsigned int version)
{
	ar >> n >> m;
	matrix = new byte[n*m];
	for (int i = 0; i < n*m; i++) {
		ar >> matrix[i];
	}
}

