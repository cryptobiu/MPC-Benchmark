#include "../../include/primitives/KProbeResistantMatrix.hpp"

void KProbeResistantMatrix::allocateKeys(vec_block_align & probeResistantKeys, block & originalKey0, block & originalKey1, size_t i, block & newKey)
{
	//Get the delta between the keys.
	block delta = _mm_xor_si128(originalKey0, originalKey1);
	int shares = 0;
	size_t lastShare = 0;
	//Get the number of shares (the number of times that "1" is shows) of the row i in the matrix.
	// This might fail if the matrix is not probe resistant, with negligible probability.
	//int res = getNumberOfShares(i, probeResistantKeys, &shares, &lastShare);
	bool allSharesAreAlreadyAssigned = true;
	block zero = _mm_setzero_si128();
	block xorOfShares = originalKey0;
	size_t j;
	auto row = matrix + i*m;
	for (j = 0; j < m; j++) {

		if (row[j] == 0) {
			// Skip on zeros and skip the last share.
			continue;
		}
		// Count the shares of bit i, and also try to find one that has not been assigned a key yet 
		// (otherwise we cannot complete the xor of all the keys).
		//Check if the keys are not set yet.
		if ((_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2], zero)) == 1) &&
			(_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2 + 1], zero)) == 1)) {
			allSharesAreAlreadyAssigned = false;
			lastShare = j;
			probeResistantKeys[j * 2] = newKey;
			probeResistantKeys[j * 2 + 1] = _mm_xor_si128(newKey, delta);
		}
		xorOfShares = _mm_xor_si128(xorOfShares, probeResistantKeys[j * 2]);
		
	}

	if (allSharesAreAlreadyAssigned) {
		cout << "error!!!" << endl;
	}
	
	xorOfShares = _mm_xor_si128(xorOfShares, probeResistantKeys[lastShare * 2]);
	/*for (size_t j = 0; j < m; j++) {
		if ((*(row.data() + j) == 0) || (j == lastShare)) {
			// Skip on zeros and skip the last share.
			continue;
		}

		//Check if the keys are not set yet.
		if ((_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2], zero)) == 1) &&
			(_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2 + 1], zero)) == 1)) {
			probeResistantKeys[j * 2] = newKey;
			probeResistantKeys[j * 2 + 1] = _mm_xor_si128(newKey, delta);
		}

		xorOfShares = _mm_xor_si128(xorOfShares, newKey);

		shares--;
		if (0 == shares) {
			// All but the last share has been allocated
			break;
		}
	}*/

	//The last pair of keys are the xor of all shares and the xor of it with delta.
	probeResistantKeys[lastShare * 2] = xorOfShares;
	probeResistantKeys[lastShare * 2 + 1] = _mm_xor_si128(xorOfShares, delta);

}

/*int KProbeResistantMatrix::getNumberOfShares(size_t i, vec_block_align &probeResistantKeys, int* shares, size_t* lastShare)
{
	bool allSharesAreAlreadyAssigned = true;
	block zero = _mm_setzero_si128();

	for (size_t j = 0; j < m; j++) {
		// Count the shares of bit i, and also try to find one that has not been assigned a key yet 
		// (otherwise we cannot complete the xor of all the keys).
		if ((*matrix)[i][j] == 1) {
			(*shares)++;

			//Check if the keys are not set yet.
			if ((_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2], zero)) == 1) &&
				(_mm_test_all_ones(_mm_cmpeq_epi8(probeResistantKeys[j * 2 + 1], zero)) == 1)) {
				allSharesAreAlreadyAssigned = false;
				*lastShare = j;
			}
		}
	}

	if (allSharesAreAlreadyAssigned) {
		return 0;
	}
	return 1;
}*/

void KProbeResistantMatrix::createMatrix(int K, int N, int t)
{
	// create object array that will hold the matrix rows
	// each row is of size m = N * t, and there are n rows.
	// java: byte[][] matrix = new byte[n][];
	matrix = new byte[n*(N*t+n)]();		 // matrix is currently holding n objects.
																		 // initialize the GF2 extension with an irreducible polynomial of size t as modulus.
																		 // essentially we are creating F_{2^t}
	NTL::GF2X gf2e_modulus = NTL::BuildIrred_GF2X(t);
	NTL::GF2E::init(gf2e_modulus);

	// for each row i in {0, ..., n-1}
	for (int i = 0; i < n; i++) {
		//set row
		calculate_k_resistant_matrix_row(i, K, N, t);
	}
}

void KProbeResistantMatrix::calculate_k_resistant_matrix_row(int index, int K, int N, int t)
{
	NTL::GF2EX p = NTL::random_GF2EX(K - 1); // gets a random polynomial in F_{2^t}[x] of degree K-1

	for (int i = 1; i <= N; i++) { // we calculate P(1)_2, ..., P(N)_2
		NTL::GF2E i_element = int_to_GF2E(i);

		// v = p(i)
		NTL::GF2X v = rep(eval(p, i_element));

		// matrix_row[j] = v;
		int first_index = (i - 1) * t;
		for (int j = 0; j < t; j++) {
			if (NTL::IsOne(NTL::coeff(v, j))) {
				matrix[index*(N*t+n)+first_index + j] = 1;
			}
			else {
				matrix[index*(N*t + n) + first_index + j] = 0;
			}
		}
	}
}

NTL::GF2E KProbeResistantMatrix::int_to_GF2E(int num)
{
	NTL::GF2X num_as_gf2x; // initially zero
	int bits = num;
	int i = 0;

	// for each bit in num, if the bit is 1, turn on the proper coeff in the gf2x polynomial
	while (bits) {
		if (bits & 1) {
			NTL::SetCoeff(num_as_gf2x, i);
		}
		i++;
		bits >>= 1;
	}

	return NTL::to_GF2E(num_as_gf2x);
}

void KProbeResistantMatrix::calculateDimensions(int k, int &t, int &K, int &N)
{
	t = (int)ceil(max(log2(n << 2), log2(k << 2)));

	while (tIsToLarge(t, k))
	{
		t -= 1;
	}

	K = (int)ceil((log2(n) + n + k) / (double)t);
	N = K + k - 1;
	m = N * t;
}

bool KProbeResistantMatrix::tIsToLarge(int t, int k)
{
	double a = (double)(1 << (t - 1));
	double b = k + ((log2(n) + n + k) / (t - 1));
	return (a > b);
}


KProbeResistantMatrix::KProbeResistantMatrix(byte* newMatrix, int n, int m)
{
	assert(newMatrix != NULL);
	assert(n != 0);

	this->matrix = newMatrix;
	this->n = n;
	this->m = m;
}

KProbeResistantMatrix::KProbeResistantMatrix(int n, int k)
{
	this->n = n;

	int t;
	int K;
	int N;

	calculateDimensions(k, t, K, N);

	//Call the native function to create the matrix.
	createMatrix(K, N, t);

	// Copy a diagonal matrix (I) on the right side of the probe resistant matrix,
	// in order to allow opportunistic allocation of shares.
	for (int i = 0; i < n; i++) {
		matrix[i*(N*t + n) + m + i] = 1;
	}
	this->m  += n;
}


vector<int> KProbeResistantMatrix::getProbeResistantLabels()
{
	vector<int> res;

	boost::push_back(res, boost::irange(0, int(this->m)));

	return res;
}

void KProbeResistantMatrix::transformKeys(vec_block_align &originalKeys, AES* mes, vec_block_align & probeResistantKeys)
{
	assert(originalKeys.size() / 2 == this->n);

	//Create vector to hold the new keys. There are two keys for each of the matrix columns.
	probeResistantKeys.resize(m * 2);

	//Generate new keys using the encryption scheme.
	auto seedByte = mes->generateKey(KEY_SIZE).getEncoded();
	vec_block_align newKeys(n);
	vec_block_align indexArray(n);

	for (int i = 0; i < n; i++)
		indexArray[i] = _mm_set_epi32(0, 0, 0, i);

	AES_KEY * aesSeedKey = (AES_KEY *)_mm_malloc(sizeof(AES_KEY), 16);
	AES_set_encrypt_key(seedByte.data(), 128, aesSeedKey);
	AES_ecb_encrypt_chunk_in_out(indexArray.data(), newKeys.data(), n, aesSeedKey);
	_mm_free(aesSeedKey);

	//For each pair of original keys allocate new keys and put them in the probeResistantKeys array.
	for (size_t i = 0; i < n; i++) {
		
		allocateKeys(probeResistantKeys, originalKeys[i * 2], originalKeys[i * 2 + 1], i, newKeys[i]);
	}
}

CircuitInput* KProbeResistantMatrix::transformInput(const CircuitInput& originalInput, PrgFromOpenSSLAES * random)
{
	auto inputSize = originalInput.size();
	assert(this->n == inputSize);
	
	shared_ptr<vector<byte>> input = originalInput.getInputVectorShared();
	// Init the new vector with -1 values.
	auto newInput = make_shared<vector<byte>>(m, 255);

	// For each input bit of the original input:
	for (size_t i = 0; i < inputSize; i++) {
		// Go over the line i in the matrix, and also over the new input vector.
		int lastIndexInTheLine = -1;
		int xorOfAllocatedBits = 0;
		for (int j = 0; j < this->m; j++) {
			// We deal with a significant bit.
			// A significant bit is ALWAYS added to the XOR.
			if (matrix[i* m + j] != 0) {
				if (newInput->at(j) == 255) {
					// This bit is not yet allocated.
					lastIndexInTheLine = j; // Use this variable to negate the case where all bits are already allocated.
					(*newInput)[j] = getRandomBit(random);
				}
				xorOfAllocatedBits = xorOfAllocatedBits ^ (*newInput)[j];
			}
			// ELSE:
			// The j^th bit in the new vector is **insignificant** to the i^th bit in the old vector
			// This bit is NOT added to the XOR.
		}
		if (lastIndexInTheLine == -1) {
			// An unallocated bit on the line was not found or have a zeros line in the matrix.
			// In any case this is an illegal state.
			throw IllegalStateException("this is not a k-probe resistant matrix: could not transform input!");
		}
		// At this point all the bits in the line were allocated, but we may have a mistake with the last bit.
		// In that case we flip it to achieve the correct xor.
		if (xorOfAllocatedBits != input->at(i)) {
			(*newInput)[lastIndexInTheLine] = (byte)(1 - (*newInput)[lastIndexInTheLine]);
		}
	}

	// There may still be un-allocated (but insignificant bits). We must make sure newInput is a binary vector.
	for (size_t j = 0; j < this->m; j++) {
		if (-1 == (*newInput)[j]) {
			(*newInput)[j] = 0;
		}
	}

	return new CircuitInput(newInput);
}

block* KProbeResistantMatrix::restoreKeys(block* receivedKeys, int size, int & returnSize)
{
	assert(size == this->m);

	//Allocate space for the original keys.

	block* restoredKeysArray = (block *)_mm_malloc(sizeof(block) * n, SIZE_OF_BLOCK);
	returnSize = n;

	//If the number of threads is more than zero, create the threads and assign to each one the appropriate circuits.
	if (CryptoPrimitives::getNumOfThreads() > 0) {
		//In case the number of thread is less than the number of circuits in the bucket, there is no point to create all the threads.
		//In this case, create only number of threads as the bucket size and assign one circuit to each thread.
		int threadCount = (CryptoPrimitives::getNumOfThreads() < n) ? CryptoPrimitives::getNumOfThreads() : n;

		vector<thread> threads;


		//Calculate the number of circuit in each thread and the remainder.
		int numOfRows = (n + threadCount-1)/ threadCount;
		int remain  = n;

		//Create the threads and assign to each one the appropriate circuits.
		//The last thread gets also the remaining circuits.
		for (int j = 0; j < threadCount; j++) {
			if (remain >= numOfRows){
				threads.push_back(thread(&KProbeResistantMatrix::restoreKeysByRow, this, receivedKeys, restoredKeysArray, j*numOfRows, (j + 1)*numOfRows));
				remain -= numOfRows;
			}
			else if (remain > 0){
				threads.push_back(thread(&KProbeResistantMatrix::restoreKeysByRow, this, receivedKeys, restoredKeysArray, j*numOfRows, (int)n));
				remain = 0;
			}
		}

		//Wait until all threads finish their job.
		for (int j = 0; j < threads.size(); j++) {
			threads[j].join();
			threads[j].~thread();
		}
		//In case no thread should be created, verify all the circuits input directly.
	}
	else {
		restoreKeysByRow(receivedKeys, restoredKeysArray, 0, (int)n);
	}
	


	return restoredKeysArray;
}

void KProbeResistantMatrix::restoreKeysByRow(block* receivedKeys, block* restoredKeysArray, int from, int to) {
	block xorOfShares;

	for (size_t i = from; i < to; i++) {
		auto row = matrix + i*m;
		xorOfShares = _mm_setzero_si128();
		for (int j = 0; j < m; j++) {

			if (0 == row[j]) {
				continue; // insignificant share
			}

			xorOfShares = _mm_xor_si128(xorOfShares, receivedKeys[j]);
		}

		restoredKeysArray[i] = xorOfShares;
	}
}

void KProbeResistantMatrix::saveToFile(string filename)
{
	/*// clean the file
	remove(filename.c_str());
	//open file
	std::ofstream outfile(filename.c_str());
	//write n - number of rows
	outfile << matrix->n << endl;
	//write m - number of column
	outfile << matrix->m << endl;

	//go over the rows and write to file
	for (const auto& a : (*matrix->matrix)) {
		outfile << vectorToString(a, ' ') << endl;
	}

	outfile.close();*/

	std::ofstream os(filename, ios::binary);
	boost::archive::binary_oarchive oa(os);
	oa << n << m;
	for (int i = 0; i < n*m; i++)
		oa << matrix[i];

}

void KProbeResistantMatrix::loadFromFile(string filename)
{
	/*//open file
	ifstream infile(filename.c_str());
	//read n - number of rows
	string line;
	getline(infile, line);
	int n = std::stoi(line);
	//read m - number of column
	getline(infile, line);
	int m = std::stoi(line);

	//read matrix by line
	shared_ptr<vector<vector<byte>>> matrix(new vector<vector<byte>>(n));
	for (int i = 0; i < n; i++) {
		//read line
		getline(infile, line);
		//get vector<byte> out of the line
		auto inputVector = readByteVectorFromString(line, ' ');
		//set in matrix
		(*matrix)[i] = inputVector;
	}
	
	
	return shared_ptr<KProbeResistantMatrix>( new KProbeResistantMatrix(matrix));
	*/

	ifstream ifs(filename.c_str(), ios::binary);
	boost::archive::binary_iarchive ia(ifs);

	ia >> n >> m;
	matrix = new byte[n*m];
	for (int i = 0; i < n*m; i++)
		ia >> matrix[i];
}
