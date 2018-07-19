#pragma once
#include <vector>
#include <libscapi/include/infra/Common.hpp>

/**
*
* This class manages the output of the circuit evaluation. <P>
*
* It contains the output bit for each output wire.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class CircuitOutput {
private:
	vector<byte> output;		//The output bit for each output wire.
								
public:
	/**
	* Constructor that sets the output for the output wires.
	* @param outputWires The output bit for each output wire.
	*/
	CircuitOutput(vector<byte> outputWires) {
		if (outputWires.size() == 0) {
			throw invalid_argument("Illegal Argument Exception");
		}

		output = outputWires;
	}

	/**
	* Returns the output bit of each output wires.
	*/
	vector<byte> getOutput() { return output; }
};

