#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>
#include "UnlockP1InputCircuitCreator.hpp"

using namespace std;

/**
* This class creates the cheating recovery circuit.
*/
class CheatingRecoveryCircuitCreator {
private:
	string circuitFilename;	// Name of cheating recovery circuit.
	int inputSize;			// Number of inputs.


public:
	/**
	 Constructor that sets the parameters.
	 input:
	 circuitFilename Name of cheating recovery circuit.
	  inputSize Number of inputs.
	*/
	CheatingRecoveryCircuitCreator(string circuitFilename, int inputSize);

	/**
	 Creates the cheating recovery circuit, if it does not exist.
	 output:
	 A garble boolean circuit that represents the cheating recovery circuit.
	*/
	GarbledBooleanCircuit* create();
};