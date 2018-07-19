#pragma once

#include <random>
#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/primitives/PrfOpenSSL.hpp>

#ifndef SIZE_OF_BLOCK
#define SIZE_OF_BLOCK 16 //size in bytes
#endif

using namespace std;

/**
* This class creates and initializes SecureRandom objects to use in the protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class SeededRandomnessProvider
{
private:
	/*
	* Unique seed for each needed secure random object.
	*/
	vector<byte> garbledCircuitSeed;
	vector<byte> p2InputKeysSeed;
	vector<byte> masksSeed;
	vector<byte> commitmentsSeed;

	PrgFromOpenSSLAES random;


public:
	static int global;
	/**
	* Creates a SecureRandom object using the given seed.
	* @param seed Used to seed the created secure random object.
	* @return The created SecureRandom object.
	*/
	static shared_ptr<PrgFromOpenSSLAES> getSeededSecureRandom(vector<byte>& seed);

	/**
	* A constructor that sets the inner members using the given seed.
	* @param seed Used to initialize the inner members.
	*/
	SeededRandomnessProvider(vector<byte>* seed);

	/**
	* Create a SecureRandom object that initialized in order to garble a circuit.
	* @return the created random.
	*/
	shared_ptr<PrgFromOpenSSLAES> getGarblingSecureRandom();

	/**
	* Create a SecureRandom object that initialized in order to generate p2 keys.
	* @return the created random.
	*/
	shared_ptr<PrgFromOpenSSLAES> getP2InputKeysSecureRandom();

	/**
	* Create a SecureRandom object that initialized in order to generate masks.
	* @return the created random.
	*/
	shared_ptr<PrgFromOpenSSLAES> getMasksSecureRandom();

	/**
	* Create a SecureRandom object that initialized in order to generate commitments.
	* @return the created random.
	*/
	shared_ptr<PrgFromOpenSSLAES> getCommitmentsSecureRandom();
};