#include "../../include/primitives/CheatingRecoveryCircuitCreator.hpp"

/**
Constructor that sets the parameters.
input:
circuitFilename Name of cheating recovery circuit.
inputSize Number of inputs.
*/
CheatingRecoveryCircuitCreator::CheatingRecoveryCircuitCreator(string cFilename, int inSize)
{
	this->circuitFilename = cFilename;
	this->inputSize = inSize;
}
/**
Creates the cheating recovery circuit, if it does not exist.
output:
A garble boolean circuit that represents the cheating recovery circuit.
*/
GarbledBooleanCircuit* CheatingRecoveryCircuitCreator::create()
{
	//check if the file exists
	//the file doesn't exists - create it
	if (!boost::filesystem::exists(this->circuitFilename)) {
		//Create an UnlockP1InputCircuitCreator class that creates the file.
		UnlockP1InputCircuitCreator(this->circuitFilename, this->inputSize).create();
	}

	return (GarbledCircuitFactory::createCircuit(this->circuitFilename,
		GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
}
