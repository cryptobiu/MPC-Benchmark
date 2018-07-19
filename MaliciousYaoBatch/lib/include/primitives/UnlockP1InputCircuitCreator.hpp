#pragma once

#include <boost/algorithm/string.hpp>
#include <vector>
#include <fstream>


using namespace std;

/**
* Utility class that creates the cheating recovery circuit file.
*/
class UnlockP1InputCircuitCreator {
private:
	string filename;			//The name of the file to creat.

	int numberOfParties;		// Number of parties of the circuit.
	int numberOfGates;			// Number of gates in the circuit.
	vector<int> numberOfInputWires;	// Number of output wires, for each party.
	int numberOfOutputWires;	// Number of output wires.

	int masterKeyLabel;			//The wire label of p2 that should enter any gate of the circuit.

	vector<vector<int>> inputLabels;	// Indices of all input wires for each party.
	vector<int> outputLabels;			// Indices of all output wires.

	/**
	 Puts the indices of the input wires in the array.
	 input:
	 currentLabel first index.
	 return:
	 the last index.
	*/
	int calculateInputLabels(int currentLabel);

	/**
	 Puts the indices of the output wires in the array.
	 input:
	 currentLabel first index.
	 return:
	 the last index.
	*/
	int calculateOutputLabels(int currentLabel);

public:
	/**
	Constructor that sets the parameters and fill internal members.
	input:
	filename The name of the file to create.
	numInputWiresP1 The number of inputs of P1.
	*/
	UnlockP1InputCircuitCreator(string filename, int numInputWiresP1);

	/**
	 Creates the circuit recovery file.
	*/
	void create();
};