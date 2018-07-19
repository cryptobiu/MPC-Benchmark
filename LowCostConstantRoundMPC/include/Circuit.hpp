/*
 * 	myDefs.h
 *
 *      Author: Aner Ben-Efraim
 *
 * 	year: 2016
 *
 */



#ifndef MYDEFS_H
#define MYDEFS_H

#pragma once

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
    int nrOfNotGates = 0;
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
    void readCircuit(const char* fileName);

    //get functions
    int getNrOfParties() { return numberOfParties; }
    vector<int> & getPartyInputs(int partyID) { return partiesInputs[partyID]; }
    vector<int> & getPartyOutputs(int partyID) { return partiesOutputs[partyID]; }
    int getNrOfAndGates() { return nrOfAndGates; }
    int getNrOfXorGates() { return nrOfXorGates; }
    int getNrOfNotGates() { return nrOfNotGates; }
    int getNrOfInput() { return nrOfInput; }
    int getNrOfOutput() { return nrOfOutput; }
    int getNrOfGates() { return (nrOfAndGates + nrOfXorGates + nrOfNotGates); }
    vector<Gate> const & getGates() const {	return gates;}
    vector<int>& getDepths(){ return depths; }

};

//#include <NTL/ZZ_p.h>
//#include <string.h>
//
//typedef unsigned char byte;
//#define STRING_BUFFER_SIZE 256
//#define flagNone 0
//#define PRECOMPUTE //No random oracle
//
//using namespace std;
//using namespace NTL;
//
//typedef struct truthTable {
//	bool FF;
//	bool FT;
//	bool TF;
//	bool TT;
//	bool Y1;
//	bool Y2;
//	bool Y3;
//	bool Y4;
//} TruthTable;
//
//
//typedef struct wire {
//
//	unsigned int number;
//	bool lambda;//the lambda
//    uint32_t* keyZero;//the keys
//    uint32_t* keyOne;//the keys
//	bool externalValue;//external value - not real value (real value XORed with lambda)
//
//	bool realLambda;//only for input/output wires
//	bool realValue;//only for input/output bits
//
//	//for Phase II
//	uint32_t* jointKey;
//
//	//for construction
//	bool negation = false;//is the value negated?
//
//	//BGW
//	ZZ_p lambdaShare;
//
//// #ifdef PRECOMPUTE
//	unsigned int fanout;
//	int* usedFanouts;
//// #endif
//
//
//} Wire;
//
//
///*
//* This struct represents one player and the array of his inputs bit serials. (Also used for output bits).
//*/
//typedef struct pPlayer {
//
//	unsigned int playerNumWires;
//
//	//obsolete. Currently used only in construction.
//	unsigned int * playerWiresIndices;
//
//	//replaced by
//	Wire **playerWires;//The input wires of the player (or the output wires of the circuit)
//} pPlayer;
//
///*
//* This struct represents one gate with two input wires, one output wire and a Truth table.
//*/
//typedef struct gate {
//	int gateNumber;
//
//	Wire *input1;
//	Wire *input2;
//	Wire *output;
//
//
//	TruthTable truthTable;
//
//	//Currently supported gates - (shifted) AND, XOR, XNOR, NOT
//	unsigned int flags : 2; //limited for 2 bits
//	bool flagNOMUL;//multiplication flag - 1 if no multiplication, 0 if there is multiplication
//	bool flagNOT; //not flag - 1 if there is not, 0 if there is no not
//
//	bool mulLambdas; //share of lambdaIn1*lambdaIn2
//	//bool mulLambdas2; //share of lambdaIn1*(-lambdaIn2 ) - can be computed locally using mulLambdas
//	//bool mulLambdas3; //share of (-lambdaIn1)*lambdaIn2  - can be computed locally using mulLambdas
//	//bool mulLambdas4; //share of (-lambdaIn1)*(-lambdaIn2) - can be computed locally using mulLambdas
//	//New gate values G[0] is Ag, G[1] is Bg, G[2] is Cg, G[3] is Dg.  Use ^Shift for shifted AND gates.
//	uint32_t* G[4];
//	//the corresponding external values
//	bool externalValues[4];
//
//	int sh = 0;//shift
//
//	//BGW
//	uint32_t mulLambdaShare;//share of multiplication of lambdas
//
//	//ZZPrecomputeExp generators[4];
////#ifdef NoRO
//#ifdef PRECOMPUTE
//	int gateFanOutNum;
//#endif
//
////#endif
//
//
//
//
//} Gate;
//
//typedef struct circuit {
//
//	Gate * gateArray;//all the gates
//	Wire * allWires;//all the wires
//
//	//number of gates
//	unsigned int numGates;
//
//	//number of players
//	unsigned int numPlayers;
//
//	//number of wires
//	unsigned int numWires;
//
//	pPlayer * playerArray;//input wires of each player
//	pPlayer outputWires;// the output wires of the cycle
//
//
//	unsigned int numOfOutputWires;
//	int numOfInputWires;
//
//    uint32_t** publicElements;
//
//#ifdef PRECOMPUTE
//	uint32_t** generators;
//#endif
//
//} Circuit;
//
//inline unsigned int charToBooleanValue(char v){
//    if (v == '1')
//    {
//        return true;
//    }
//    return false;
//}
//
//int setFanOut(Circuit* circuit);
//Gate GateCreator(const unsigned int inputBit1, const unsigned int inputBit2, const unsigned int outputBit, TruthTable TTable, Wire * wireArray, unsigned int number);
//TruthTable createTruthTablefFromChars(char FF, char FT, char TF, char TT);
//void removeSpacesAndTabs(char* source);
//
///*
// * This function gets a path to a file that represents a circuit (format instructions below).
// *
// * Returns a Circuit struct.
// *
// */
//Circuit * readCircuitFromFile(char* path);

#endif
