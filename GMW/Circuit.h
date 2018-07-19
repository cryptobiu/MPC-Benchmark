//
// Created by moriya on 04/01/17.
//

#ifndef GMW_CIRCUIT_H
#define GMW_CIRCUIT_H

#include <vector>
#include <fstream>
#include <iostream>
#include "../../include/infra/Common.hpp"

using namespace std;

/**
* The Gate struct is a software representation of a circuit's gate, that is the structure of the circuit and not the actuall values assigned.
* It contains a type that performs a logical function on the values of the input wires (input1 and input2)  and assigns
* that value to the output wire for xor and and gates. The gates may also be of type input/output and for these gates
* there is the party attribute that represents the owner.
*/
struct Gate
{
    int inFan;          //number of input wires
    int outFan;         //number of output wires
    int inputIndex1;    //the 0-gate index, relevant for xor/and/output
    int inputIndex2;    //the 1-gate index, relevant for xor/and
    int outputIndex;    //the output index of this gate, relevant for input/xor/and
    int gateType;       //the type of the gate, can be logical, that is, xor or and or an input/output gate.
};

/**
 * The circuit class represents the circuit file given by the user.
 * It contains an array of gates, the inputs and outputs of the parties, along with other general parameters.
 * The depths of the circuit are the amounts of gates that can be computed in parallel in each level.
 * The circuit also contains some function related to the circuit, for example a function that read the circuit file and build the circuit.
*/
class Circuit {

private:
    vector<Gate> gates;
    vector<vector<int>> partiesInputs;
    vector<vector<int>> partiesOutputs;
    int numberOfParties = 0;
    int nrOfAndGates = 0;
    int nrOfXorGates = 0;
    int nrOfInput = 0;
    int nrOfOutput = 0;
    vector<int> depths;

	/*
	 * Gets a binary representation of a number and return the decimal representation of it.
	 * This function is used on the gates truth table.
	 */
    int binaryTodecimal(int n); 

	/*
	 * This function rearrange the circuit to the optimal structure, making the depth of the circuit smallest.
	 */
    void reArrangeCircuit();
public:

    /**
    * This method reads text file and creates an object of ArythmeticCircuit according to the file.
    * This includes creating the gates and other information about the parties involved.
    *
    */
    void readCircuit(const string fileName);

    //get functions
    int getNrOfParties() { return numberOfParties; }
    vector<int> & getPartyInputs(int partyID) { return partiesInputs[partyID]; }
    vector<int> & getPartyOutputs(int partyID) { return partiesOutputs[partyID]; }
    int getNrOfAndGates() { return nrOfAndGates; }
    int getNrOfXorGates() { return nrOfXorGates; }
    int getNrOfInput() { return nrOfInput; }
    int getNrOfOutput() { return nrOfOutput; }
    int getNrOfGates() { return (nrOfAndGates + nrOfXorGates); }
    vector<Gate> const & getGates() const {	return gates;}
    vector<int>& getDepths(){ return depths; }

};


#endif //GMW_CIRCUIT_H
